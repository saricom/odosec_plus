# -*- coding: utf-8 -*-
"""
OdoSec Plus — Immutable Audit Log Model
========================================
Write-once log of all ORM operations captured by the audit mixin.
Non-superadmin users are blocked from modifying or deleting entries.
Each entry carries a SHA-256 tamper-detection hash.
"""
import hashlib

from odoo import models, fields, api
from odoo.exceptions import AccessError


class OdooSecAuditLog(models.Model):
    _name        = 'odosec.audit.log'
    _description = 'OdoSec Plus — Audit Log'
    _order       = 'timestamp desc, id desc'
    _log_access  = False          # Disable Odoo's own write_date / write_uid
    _rec_name    = 'display_name_computed'

    # ── Event identity ────────────────────────────────────────────────────────
    user_id       = fields.Many2one(
        'res.users', string='User', readonly=True,
        ondelete='restrict', index=True,
    )
    user_name     = fields.Char(
        related='user_id.name', store=True, readonly=True, string='User Name',
    )
    model_name    = fields.Char(
        string='Model', readonly=True, index=True,
    )
    record_id     = fields.Integer(
        string='Record ID', readonly=True, index=True,
    )
    action_type   = fields.Selection([
        ('create',       'Create'),
        ('write',        'Update'),
        ('unlink',       'Delete'),
        ('read',         'Read (Sensitive)'),
        ('export',       'Export'),
        ('login',        'Login'),
        ('login_failed', 'Login Failed'),
    ], string='Action', readonly=True, index=True, required=True)

    # ── Value delta ───────────────────────────────────────────────────────────
    old_values    = fields.Text(string='Old Values (JSON)', readonly=True)
    new_values    = fields.Text(string='New Values (JSON)', readonly=True)

    # ── Context ───────────────────────────────────────────────────────────────
    timestamp     = fields.Datetime(
        string='Timestamp', readonly=True, index=True,
        default=fields.Datetime.now,
    )
    ip_address    = fields.Char(string='IP Address', readonly=True, size=64)
    session_id    = fields.Char(string='Session ID', readonly=True, size=256)
    additional_info = fields.Text(string='Additional Info', readonly=True)

    # ── Integrity ─────────────────────────────────────────────────────────────
    tamper_hash   = fields.Char(
        string='Integrity Hash (SHA-256)', readonly=True, size=64,
    )
    integrity_ok  = fields.Boolean(
        string='Hash Valid', compute='_compute_integrity', store=False,
    )

    # ── Display ───────────────────────────────────────────────────────────────
    display_name_computed = fields.Char(
        string='Reference', compute='_compute_display_name', store=True,
    )

    # ── SQL constraints ───────────────────────────────────────────────────────
    _sql_constraints = [
        ('tamper_hash_not_null',
         'CHECK(tamper_hash IS NOT NULL)',
         'Integrity hash must not be null.'),
    ]

    # ── Compute methods ───────────────────────────────────────────────────────
    @api.depends('action_type', 'model_name', 'record_id')
    def _compute_display_name(self):
        for rec in self:
            action = (rec.action_type or '').upper()
            rec.display_name_computed = (
                f"[{action}] {rec.model_name or '?'} #{rec.record_id}"
            )

    def _compute_integrity(self):
        for rec in self:
            if rec.tamper_hash and rec.timestamp:
                expected = self._build_hash(
                    rec.user_id.id, rec.model_name, rec.record_id,
                    rec.action_type, fields.Datetime.to_string(rec.timestamp),
                )
                rec.integrity_ok = (rec.tamper_hash == expected)
            else:
                rec.integrity_ok = False

    # ── Tamper resistance: block write / unlink for non-superusers ────────────
    def write(self, vals):
        if not self.env.su:
            raise AccessError(
                'OdoSec Plus: Audit logs are immutable. '
                'Modifications are not permitted.'
            )
        return super().write(vals)

    def unlink(self):
        if not self.env.su:
            raise AccessError(
                'OdoSec Plus: Audit logs cannot be deleted.'
            )
        return super().unlink()

    # ── Public helpers ────────────────────────────────────────────────────────
    @staticmethod
    def _build_hash(uid, model, record_id, action, ts_str):
        """Build a deterministic SHA-256 integrity hash for a log entry."""
        raw = f"{uid}|{model}|{record_id}|{action}|{ts_str}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def action_verify_integrity(self):
        """Button action: re-verify all visible records' hashes."""
        tampered = self.filtered(lambda r: not r.integrity_ok)
        if tampered:
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': 'Integrity Check Failed',
                    'message': (
                        f'{len(tampered)} record(s) have been tampered with. '
                        'IDs: ' + ', '.join(str(r.id) for r in tampered)
                    ),
                    'type': 'danger',
                    'sticky': True,
                },
            }
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'Integrity Check Passed',
                'message': f'All {len(self)} records are intact.',
                'type': 'success',
                'sticky': False,
            },
        }

    # ── Retention cleanup (called by cron) ────────────────────────────────────
    @api.model
    def action_archive_old_logs(self):
        """Remove logs older than retention period (configurable via system parameter)."""
        param = self.env['ir.config_parameter'].sudo()
        retention_days = int(param.get_param('odosec.log_retention_days', 365))
        cutoff = fields.Datetime.subtract(
            fields.Datetime.now(), days=retention_days
        )
        old_logs = self.sudo().search([('timestamp', '<', cutoff)])
        count = len(old_logs)
        if old_logs:
            old_logs.sudo().unlink()
        return count
