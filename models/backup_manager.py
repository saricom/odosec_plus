# -*- coding: utf-8 -*-
"""
OdoSec Plus — Backup Manager Model
=====================================
Manages encrypted database backup records and triggers.
Access is restricted exclusively to System Administrators.
"""
import datetime

from odoo import models, fields, api
from odoo.exceptions import AccessError, UserError


class OdooSecBackupManager(models.Model):
    _name        = 'odosec.backup.manager'
    _description = 'OdoSec Plus — Backup Manager'
    _order       = 'create_date desc'
    _rec_name    = 'name'

    # ── Fields ────────────────────────────────────────────────────────────────
    name         = fields.Char(string='Backup Name', readonly=True)
    state        = fields.Selection([
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('done',    'Completed'),
        ('failed',  'Failed'),
    ], default='pending', readonly=True, index=True, string='Status')
    backup_size  = fields.Float(string='Size (MB)', readonly=True, digits=(10, 2))
    file_path    = fields.Char(string='Encrypted File Path', readonly=True)
    error_msg    = fields.Text(string='Error Details', readonly=True)
    triggered_by = fields.Many2one(
        'res.users', string='Triggered By', readonly=True,
        default=lambda self: self.env.uid,
    )
    notes        = fields.Text(string='Notes')
    duration_sec = fields.Float(string='Duration (s)', readonly=True)
    create_date  = fields.Datetime(string='Triggered At', readonly=True)

    # ── Computed / display ────────────────────────────────────────────────────
    can_download = fields.Boolean(
        compute='_compute_can_download', string='Can Download',
    )

    @api.depends('state', 'file_path')
    def _compute_can_download(self):
        is_admin = self.env.user.has_group('base.group_system')
        for rec in self:
            rec.can_download = (
                rec.state == 'done'
                and bool(rec.file_path)
                and is_admin
            )

    # ── Access guard ──────────────────────────────────────────────────────────
    def _assert_admin(self):
        if not self.env.user.has_group('base.group_system'):
            raise AccessError(
                'OdoSec Plus: Only System Administrators can manage backups.'
            )

    # ── Actions ───────────────────────────────────────────────────────────────
    @api.model
    def action_trigger_backup(self):
        """
        Create a new backup record, execute the backup service,
        and return the completed record.
        Restricted to System Administrator.
        """
        self._assert_admin()

        ts_str = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        rec = self.create({
            'name':         f'odosec_backup_{ts_str}',
            'state':        'running',
            'triggered_by': self.env.uid,
        })
        # Flush to DB so a crash mid-backup still shows the running record
        rec.flush_model()

        import time
        t0 = time.monotonic()
        try:
            from ..services.backup_service import BackupService
            svc = BackupService(self.env)
            file_path, size_mb = svc.create_encrypted_backup(rec.name)
            elapsed = round(time.monotonic() - t0, 1)
            rec.write({
                'state':        'done',
                'file_path':    file_path,
                'backup_size':  size_mb,
                'duration_sec': elapsed,
            })
            # Audit log
            self.env['odosec.audit.log'].sudo().create({
                'user_id':     self.env.uid,
                'model_name':  'odosec.backup.manager',
                'record_id':   rec.id,
                'action_type': 'create',
                'additional_info': f'Backup completed: {rec.name} ({size_mb} MB)',
                'tamper_hash': self.env['odosec.audit.log']._build_hash(
                    self.env.uid, 'odosec.backup.manager', rec.id,
                    'create',
                    fields.Datetime.to_string(fields.Datetime.now()),
                ),
            })
        except Exception as exc:
            rec.write({'state': 'failed', 'error_msg': str(exc)})
            raise UserError(f'OdoSec Plus: Backup failed — {exc}') from exc

        return {
            'type': 'ir.actions.client',
            'tag':  'display_notification',
            'params': {
                'title':   'Backup Completed',
                'message': f'{rec.name} ({rec.backup_size} MB) ready for download.',
                'type':    'success',
                'sticky':  False,
                'next': {
                    'type': 'ir.actions.act_window',
                    'res_model': 'odosec.backup.manager',
                    'res_id': rec.id,
                    'view_mode': 'form',
                },
            },
        }

    def action_download(self):
        """Redirect user to the encrypted file download endpoint."""
        self._assert_admin()
        self.ensure_one()
        if self.state != 'done':
            raise UserError('OdoSec Plus: Backup is not in a completed state.')
        return {
            'type': 'ir.actions.act_url',
            'url':  f'/odosec/backup/download/{self.id}',
            'target': 'self',
        }

    def action_delete_file(self):
        """Delete the physical backup file from disk (admin only)."""
        self._assert_admin()
        self.ensure_one()
        import os
        if self.file_path and os.path.isfile(self.file_path):
            os.remove(self.file_path)
        self.write({'file_path': False, 'state': 'pending'})

    # ── Cleanup cron ──────────────────────────────────────────────────────────
    @api.model
    def action_cleanup_old_backups(self):
        """Remove backup files older than retention period."""
        import os
        param = self.env['ir.config_parameter'].sudo()
        days  = int(param.get_param('odosec.backup_retention_days', 30))
        cutoff = fields.Datetime.subtract(fields.Datetime.now(), days=days)
        old = self.sudo().search([
            ('state', '=', 'done'),
            ('create_date', '<', cutoff),
        ])
        for rec in old:
            if rec.file_path and os.path.isfile(rec.file_path):
                os.remove(rec.file_path)
        old.sudo().unlink()
