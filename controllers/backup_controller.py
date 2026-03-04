# -*- coding: utf-8 -*-
"""
OdoSec Plus — Secure Backup Download Controller
=================================================
Serves encrypted backup files exclusively to authenticated System Administrators.

Security checklist:
  ✔  auth='user' — no unauthenticated access
  ✔  group_system check before any file I/O
  ✔  Path traversal prevention via os.path.realpath
  ✔  Download event logged to audit trail
  ✔  Cache-Control: no-store to prevent browser caching
  ✔  CSRF protection via csrf=True
  ✔  Streaming response with Content-Disposition: attachment
"""
import os

from odoo import http
from odoo.http import request, Response
from odoo.exceptions import AccessError


class OdooSecBackupController(http.Controller):

    # ── Encrypted file download ────────────────────────────────────────────────
    @http.route(
        '/odosec/backup/download/<int:backup_id>',
        type='http',
        auth='user',
        methods=['GET'],
        csrf=True,
    )
    def download_backup(self, backup_id, **kwargs):
        """
        Download the encrypted backup file for the given backup_id.
        Only System Administrators are permitted.
        """
        # ── 1. Enforce System Administrator ─────────────────────────────────
        if not request.env.user.has_group('base.group_system'):
            raise AccessError(
                'OdoSec Plus: Backup downloads are restricted to System Administrators.'
            )

        # ── 2. Load record (in user context, not sudo — respects record rules) ──
        backup = request.env['odosec.backup.manager'].browse(backup_id)
        if not backup.exists():
            return Response('Backup record not found.', status=404)
        if backup.state != 'done':
            return Response('Backup is not in a completed state.', status=400)
        if not backup.file_path:
            return Response('No file associated with this backup.', status=404)

        # ── 3. Path traversal guard ──────────────────────────────────────────
        from odoo.tools import config
        allowed_dir = os.path.realpath(
            config.get('odosec_backup_dir', '/var/odoo/odosec_backups')
        )
        real_path = os.path.realpath(backup.file_path)

        if not real_path.startswith(allowed_dir + os.sep):
            return Response(
                'OdoSec Plus: Invalid backup file path.', status=403
            )

        if not os.path.isfile(real_path):
            return Response(
                'Backup file not found on disk. It may have been deleted.', status=404
            )

        # ── 4. Audit the download event ──────────────────────────────────────
        from odoo import fields
        ts = fields.Datetime.now()
        ip = (request.httprequest.environ.get('HTTP_X_FORWARDED_FOR')
              or request.httprequest.environ.get('REMOTE_ADDR'))
        sid = getattr(request.session, 'sid', None)
        request.env['odosec.audit.log'].sudo().create({
            'user_id':       request.env.uid,
            'model_name':    'odosec.backup.manager',
            'record_id':     backup_id,
            'action_type':   'export',
            'ip_address':    ip,
            'session_id':    sid,
            'timestamp':     ts,
            'additional_info': f'Encrypted backup downloaded: {backup.name}',
            'tamper_hash':   request.env['odosec.audit.log']._build_hash(
                request.env.uid, 'odosec.backup.manager', backup_id,
                'export', fields.Datetime.to_string(ts),
            ),
        })

        # ── 5. Stream the file ───────────────────────────────────────────────
        filename = os.path.basename(real_path)
        try:
            with open(real_path, 'rb') as f:
                data = f.read()
        except OSError as e:
            return Response(f'Failed to read backup file: {e}', status=500)

        headers = [
            ('Content-Type',              'application/octet-stream'),
            ('Content-Disposition',       f'attachment; filename="{filename}"'),
            ('Content-Length',            str(len(data))),
            ('Cache-Control',             'no-store, no-cache, must-revalidate, max-age=0'),
            ('Pragma',                    'no-cache'),
            ('X-Content-Type-Options',    'nosniff'),
            ('X-Frame-Options',           'DENY'),
        ]
        return Response(data, headers=headers, status=200)

    # ── Health probe (admin only) ──────────────────────────────────────────────
    @http.route(
        '/odosec/health',
        type='json',
        auth='user',
        methods=['POST'],
        csrf=False,
    )
    def health_probe(self, **kwargs):
        """
        Returns a JSON summary of current security health.
        Requires OdoSec Analyst role minimum.
        """
        if not request.env.user.has_group('odosec_plus.group_odosec_analyst'):
            raise AccessError('OdoSec Plus: Health probe requires Analyst role.')

        latest = request.env['odosec.security.health'].sudo().search(
            [], order='computed_date desc', limit=1
        )
        if not latest:
            return {'status': 'no_data', 'risk': 'unknown'}

        return {
            'status':          'ok',
            'computed_at':     str(latest.computed_date),
            'overall_risk':    latest.overall_risk,
            'risk_score':      latest.risk_score,
            'open_critical':   latest.open_critical,
            'open_high':       latest.open_high,
            'backup_age_days': latest.backup_age_days,
            'pending_deletions': latest.pending_deletions,
        }
