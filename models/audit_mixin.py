# -*- coding: utf-8 -*-
"""
OdoSec Plus — Audit Mixin & Deletion Governance Mixin
=======================================================
Abstract models intended to be inherited by any protected model.

Usage:
    class SaleOrder(models.Model):
        _name   = 'sale.order'
        _inherit = ['sale.order', 'odosec.audit.mixin']
        _odosec_sensitive_fields = ['amount_total', 'partner_id']

Deletion governance:
    class AccountMove(models.Model):
        _name   = 'account.move'
        _inherit = ['account.move', 'odosec.deletion.mixin']
"""
import json

from odoo import models, fields, api
from odoo.exceptions import AccessError, UserError
from odoo.http import request


# ── Utility: safe request context extraction ─────────────────────────────────

def _get_request_context():
    """Returns (ip_address, session_id) from the current HTTP request, or (None, None)."""
    try:
        if request and request.httprequest:
            ip  = request.httprequest.environ.get('HTTP_X_FORWARDED_FOR') or \
                  request.httprequest.environ.get('REMOTE_ADDR')
            sid = getattr(request.session, 'sid', None)
            return ip, sid
    except RuntimeError:
        pass
    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT MIXIN
# ─────────────────────────────────────────────────────────────────────────────

class OdooSecAuditMixin(models.AbstractModel):
    """
    Inherit this mixin to enable transparent ORM-level audit logging.

    Class attributes (optional, override in subclass):
        _odosec_writable_fields  : list[str] — allowlist for mass-assignment guard
        _odosec_sensitive_fields : list[str] — fields triggering special audit flag
        _odosec_skip_fields      : list[str] — fields to exclude from old/new capture
    """
    _name        = 'odosec.audit.mixin'
    _description = 'OdoSec Plus — Audit Mixin'

    _odosec_writable_fields   = []   # If non-empty, enforce allowlist on write
    _odosec_sensitive_fields  = []   # Sensitive fields get extra log annotation
    _odosec_skip_fields       = [    # Excluded from value capture (too large/binary)
        'message_ids', 'activity_ids', 'website_message_ids',
        '__last_update', 'write_date', 'create_date',
        'write_uid', 'create_uid',
    ]

    # ── Internal log emitter ──────────────────────────────────────────────────

    def _odosec_emit_log(self, action_type, record_id,
                         old_vals=None, new_vals=None, extra=None):
        """
        Core log emission. Creates a single odosec.audit.log record.
        Always executes under sudo() so record rules don't block the write.
        """
        ip, sid = _get_request_context()
        ts = fields.Datetime.now()

        self.env['odosec.audit.log'].sudo().create({
            'user_id':       self.env.uid,
            'model_name':    self._name,
            'record_id':     record_id,
            'action_type':   action_type,
            'old_values':    json.dumps(old_vals, default=str) if old_vals else False,
            'new_values':    json.dumps(new_vals, default=str) if new_vals else False,
            'ip_address':    ip,
            'session_id':    sid,
            'timestamp':     ts,
            'additional_info': extra,
            'tamper_hash':   self.env['odosec.audit.log']._build_hash(
                self.env.uid, self._name, record_id, action_type,
                fields.Datetime.to_string(ts),
            ),
        })

    def _odosec_capture_old_values(self, vals):
        """
        Snapshot current field values for fields present in vals.
        Excludes computed, related, and skip-listed fields.
        """
        audited = [
            f for f in vals
            if f in self._fields
            and f not in self._odosec_skip_fields
            and not self._fields[f].compute
            and not self._fields[f].related
        ]
        result = {}
        for record in self:
            snapshot = {}
            for f in audited:
                try:
                    snapshot[f] = self._fields[f].convert_to_write(
                        record[f], record
                    )
                except Exception:
                    snapshot[f] = str(record[f])
            result[record.id] = snapshot
        return result, audited

    # ── ORM override: create ──────────────────────────────────────────────────

    @api.model_create_multi
    def create(self, vals_list):
        records = super().create(vals_list)
        for record, vals in zip(records, vals_list):
            safe_vals = {
                k: v for k, v in vals.items()
                if k not in self._odosec_skip_fields
            }
            extra = None
            if self._odosec_sensitive_fields:
                hits = set(safe_vals) & set(self._odosec_sensitive_fields)
                if hits:
                    extra = f'SENSITIVE fields set on create: {sorted(hits)}'
            self._odosec_emit_log(
                'create', record.id,
                old_vals={},
                new_vals=safe_vals,
                extra=extra,
            )
        return records

    # ── ORM override: write ───────────────────────────────────────────────────

    def write(self, vals):
        # Mass-assignment guard
        if self._odosec_writable_fields and not self.env.su:
            disallowed = set(vals) - set(self._odosec_writable_fields) - \
                         set(self._odosec_skip_fields)
            if disallowed:
                raise AccessError(
                    f'OdoSec Plus: Mass assignment blocked. '
                    f'Fields not in allowlist: {sorted(disallowed)}'
                )

        old_map, audited_fields = self._odosec_capture_old_values(vals)
        result = super().write(vals)

        for record in self:
            new_vals = {f: vals[f] for f in audited_fields if f in vals}
            extra = None
            if self._odosec_sensitive_fields:
                hits = set(new_vals) & set(self._odosec_sensitive_fields)
                if hits:
                    extra = f'SENSITIVE fields modified: {sorted(hits)}'
            self._odosec_emit_log(
                'write', record.id,
                old_vals=old_map.get(record.id, {}),
                new_vals=new_vals,
                extra=extra,
            )
        return result

    # ── ORM override: unlink ──────────────────────────────────────────────────

    def unlink(self):
        for record in self:
            snapshot = {}
            for f in record._fields:
                if (f not in self._odosec_skip_fields
                        and not record._fields[f].compute
                        and not record._fields[f].related):
                    try:
                        snapshot[f] = record._fields[f].convert_to_write(
                            record[f], record
                        )
                    except Exception:
                        snapshot[f] = str(record[f])
            self._odosec_emit_log('unlink', record.id, old_vals=snapshot, new_vals={})
        return super().unlink()


# ─────────────────────────────────────────────────────────────────────────────
# DELETION GOVERNANCE MIXIN
# ─────────────────────────────────────────────────────────────────────────────

# Models that require approval before deletion
GOVERNED_MODELS = [
    'sale.order',
    'purchase.order',
    'account.move',
    'hr.payslip',
    'res.users',
    'product.template',
    'stock.picking',
]


class OdooSecDeletionMixin(models.AbstractModel):
    """
    Inherit this mixin to route unlink() through the deletion governance workflow.
    Unlink is intercepted and replaced with a DeletionRequest.
    Actual deletion only proceeds after an approved DeletionRequest calls
    _execute_approved_deletion() with the '_odosec_deletion_approved' context flag.
    """
    _name        = 'odosec.deletion.mixin'
    _description = 'OdoSec Plus — Deletion Governance Mixin'

    def unlink(self):
        if self._name in GOVERNED_MODELS:
            ctx = self.env.context
            if not ctx.get('_odosec_deletion_approved'):
                import json as _json
                for record in self:
                    # Build a human-readable snapshot
                    snap = {}
                    for f in ('name', 'state', 'create_date', 'partner_id'):
                        if f in record._fields:
                            try:
                                snap[f] = str(record[f])
                            except Exception:
                                pass
                    self.env['odosec.deletion.request'].sudo().create({
                        'model_name':  self._name,
                        'record_id':   record.id,
                        'record_repr': _json.dumps(snap, default=str),
                        'requested_by': self.env.uid,
                    })
                raise UserError(
                    'OdoSec Plus: Deletion requires System Administrator approval.\n'
                    'A deletion request has been created and sent for review.'
                )
        return super().unlink()

    # ── IDOR guard ────────────────────────────────────────────────────────────

    @api.model
    def odosec_check_access(self, record_id):
        """
        IDOR guard: verify the current user's domain includes this record_id.
        Raises AccessError if the record is not in the user's accessible domain.
        Call from controllers before serving a record by raw ID.
        """
        record = self.search([('id', '=', record_id)])
        if not record:
            # Emit a suspicious access log
            from odoo.http import request as _req
            ip, sid = _get_request_context()
            ts = fields.Datetime.now()
            self.env['odosec.audit.log'].sudo().create({
                'user_id':     self.env.uid,
                'model_name':  self._name,
                'record_id':   record_id,
                'action_type': 'read',
                'ip_address':  ip,
                'session_id':  sid,
                'timestamp':   ts,
                'additional_info': 'IDOR attempt: record not in user domain',
                'tamper_hash': self.env['odosec.audit.log']._build_hash(
                    self.env.uid, self._name, record_id, 'read',
                    fields.Datetime.to_string(ts),
                ),
            })
            raise AccessError(
                'OdoSec Plus: Access denied — record not in your domain.'
            )
        return record
