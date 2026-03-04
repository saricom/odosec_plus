# -*- coding: utf-8 -*-
"""OdoSec Plus — Login Rate Limiter"""
from datetime import timedelta
from odoo import models, fields, api
from odoo.exceptions import AccessError

MAX_ATTEMPTS    = 5
LOCKOUT_MINUTES = 15


class OdooSecRateLimiter(models.Model):
    _name        = 'odosec.rate.limiter'
    _description = 'OdoSec Plus — Login Rate Limiter'
    _order       = 'last_attempt desc'
    _rec_name    = 'login'

    login        = fields.Char(string='Login', required=True, index=True)
    ip_address   = fields.Char(string='IP Address', index=True)
    attempts     = fields.Integer(string='Failed Attempts', default=0)
    last_attempt = fields.Datetime(string='Last Attempt')
    locked_until = fields.Datetime(string='Locked Until')
    is_locked    = fields.Boolean(
        compute='_compute_is_locked', string='Currently Locked', store=False,
    )

    def _compute_is_locked(self):
        now = fields.Datetime.now()
        for rec in self:
            rec.is_locked = bool(rec.locked_until and rec.locked_until > now)

    # ── Core logic ────────────────────────────────────────────────────────────
    @api.model
    def check_and_record_attempt(self, login, ip):
        """
        Called before processing a login attempt.
        Records the attempt and raises AccessError if the account is locked.
        """
        now = fields.Datetime.now()
        record = self.sudo().search(
            [('login', '=', login), ('ip_address', '=', ip)],
            limit=1,
        )
        if record:
            # Check lockout
            if record.locked_until and record.locked_until > now:
                raise AccessError(
                    f'OdoSec Plus: Too many failed login attempts. '
                    f'Account locked until {record.locked_until} UTC.'
                )
            new_attempts = record.attempts + 1
            locked_until = False
            if new_attempts >= MAX_ATTEMPTS:
                locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            record.sudo().write({
                'attempts':     new_attempts,
                'last_attempt': now,
                'locked_until': locked_until,
            })
        else:
            self.sudo().create({
                'login':        login,
                'ip_address':   ip,
                'attempts':     1,
                'last_attempt': now,
            })

    @api.model
    def reset_on_success(self, login, ip):
        """Call after a successful login to clear the rate-limit record."""
        self.sudo().search(
            [('login', '=', login), ('ip_address', '=', ip)]
        ).unlink()

    @api.model
    def cleanup_expired(self):
        """Cron: Remove unlocked, old records to keep the table lean."""
        now = fields.Datetime.now()
        cutoff = now - timedelta(hours=24)
        expired = self.sudo().search([
            '|',
            ('locked_until', '<', now),
            '&',
            ('locked_until', '=', False),
            ('last_attempt', '<', cutoff),
        ])
        expired.sudo().unlink()

    # ── Admin actions ─────────────────────────────────────────────────────────
    def action_unlock(self):
        """Admin: manually unlock an account."""
        self.write({'locked_until': False, 'attempts': 0})
