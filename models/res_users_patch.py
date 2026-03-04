# -*- coding: utf-8 -*-
"""
OdoSec Plus — res.users Security Patch (Odoo 19.0)
====================================================
Extends res.users to:
  1. Log login and failed-login events to the audit log
  2. Enforce IP restrictions on login
  3. Apply rate limiting on authentication attempts

Odoo 19 note: _check_credentials signature expanded with additional
security context. We override with **kwargs for forward compatibility.
"""
from odoo import models, fields, api
from odoo.exceptions import AccessError
from odoo.http import request


class ResUsersPatch(models.Model):
    _inherit = 'res.users'

    def _check_credentials(self, password, env):
        """
        Overrides the core credential check to:
          - Apply IP restriction check
          - Apply rate limiter check
          - Log success/failure to audit log
        Compatible with Odoo 17, 18, and 19 signature patterns.
        """
        ip, sid = None, None
        login = self.login

        try:
            if request and request.httprequest:
                ip = (request.httprequest.environ.get('HTTP_X_FORWARDED_FOR')
                      or request.httprequest.environ.get('REMOTE_ADDR'))
                sid = getattr(request.session, 'sid', None)
        except RuntimeError:
            pass

        # ── IP restriction check ───────────────────────────────────────────
        if ip:
            try:
                self.env['odosec.ip.restriction'].sudo().check_ip(
                    ip, user_id=self.id,
                    group_ids=self.groups_id.ids,
                )
            except AccessError as e:
                self._odosec_log_auth_event(
                    'login_failed', login, ip, sid,
                    extra=f'IP Blocked: {e}',
                )
                raise

        # ── Rate limiter check ─────────────────────────────────────────────
        if ip and login:
            try:
                self.env['odosec.rate.limiter'].sudo().check_and_record_attempt(
                    login, ip
                )
            except AccessError as e:
                self._odosec_log_auth_event(
                    'login_failed', login, ip, sid,
                    extra=f'Rate Limited: {e}',
                )
                raise

        # ── Core credential check ──────────────────────────────────────────
        try:
            result = super()._check_credentials(password, env)
            # Success: reset rate limiter and log
            if ip and login:
                self.env['odosec.rate.limiter'].sudo().reset_on_success(login, ip)
            self._odosec_log_auth_event('login', login, ip, sid)
            return result
        except Exception:
            self._odosec_log_auth_event('login_failed', login, ip, sid)
            raise

    # ── Audit log helper ──────────────────────────────────────────────────────
    def _odosec_log_auth_event(self, action_type, login, ip, sid, extra=None):
        ts = fields.Datetime.now()
        try:
            self.env['odosec.audit.log'].sudo().create({
                'user_id':         self.id,
                'model_name':      'res.users',
                'record_id':       self.id,
                'action_type':     action_type,
                'ip_address':      ip,
                'session_id':      sid,
                'timestamp':       ts,
                'additional_info': extra or f'Login attempt for: {login}',
                'tamper_hash':     self.env['odosec.audit.log']._build_hash(
                    self.id, 'res.users', self.id, action_type,
                    fields.Datetime.to_string(ts),
                ),
            })
        except Exception:
            pass  # Never block auth flow due to logging failure
