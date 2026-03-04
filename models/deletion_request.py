# -*- coding: utf-8 -*-
"""
OdoSec Plus — Deletion Governance Request Model
=================================================
Full state-machine workflow for governed record deletions.
Inherits mail.thread for chatter-based decision trail.
"""
from odoo import models, fields, api
from odoo.exceptions import AccessError, UserError


class OdooSecDeletionRequest(models.Model):
    _name        = 'odosec.deletion.request'
    _description = 'OdoSec Plus — Deletion Request'
    _inherit     = ['mail.thread', 'mail.activity.mixin']
    _order       = 'create_date desc'
    _rec_name    = 'name'

    # ── Core fields ───────────────────────────────────────────────────────────
    name           = fields.Char(
        string='Reference', required=True, copy=False,
        default=lambda self: self.env['ir.sequence'].next_by_code(
            'odosec.deletion.request') or 'DEL-NEW',
    )
    state          = fields.Selection([
        ('draft',    'Draft'),
        ('pending',  'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ], default='draft', string='Status', tracking=True,
       index=True, copy=False)

    # ── Target record ─────────────────────────────────────────────────────────
    model_name     = fields.Char(
        string='Target Model', required=True, readonly=True,
    )
    record_id      = fields.Integer(
        string='Target Record ID', required=True, readonly=True,
    )
    record_repr    = fields.Text(
        string='Record Snapshot (JSON)', readonly=True,
        help='Snapshot of key fields captured at request time.',
    )
    model_display  = fields.Char(
        string='Model Description',
        compute='_compute_model_display', store=True,
    )

    # ── Actors ────────────────────────────────────────────────────────────────
    requested_by   = fields.Many2one(
        'res.users', string='Requested By', readonly=True,
        default=lambda self: self.env.uid, index=True,
    )
    approved_by    = fields.Many2one(
        'res.users', string='Decision By', readonly=True, copy=False,
    )

    # ── Decision metadata ─────────────────────────────────────────────────────
    decision_note  = fields.Text(string='Decision Note', tracking=True)
    decision_date  = fields.Datetime(string='Decision Date', readonly=True)
    urgency        = fields.Selection([
        ('low',     'Low'),
        ('normal',  'Normal'),
        ('high',    'High'),
        ('critical','Critical'),
    ], default='normal', string='Urgency', tracking=True)

    # FIX: justification is NOT required=True at DB level so the mixin can
    # auto-create requests; it is enforced only through the UI submit button.
    justification  = fields.Text(
        string='Business Justification',
        help='Explain why this record must be deleted.',
    )

    # ── Computed ──────────────────────────────────────────────────────────────
    @api.depends('model_name')
    def _compute_model_display(self):
        for rec in self:
            if rec.model_name:
                model_obj = self.env['ir.model'].sudo().search(
                    [('model', '=', rec.model_name)], limit=1
                )
                rec.model_display = model_obj.name or rec.model_name
            else:
                rec.model_display = ''

    # ── Transition: Submit for approval ───────────────────────────────────────
    def action_submit(self):
        self.ensure_one()
        if self.state != 'draft':
            raise UserError('OdoSec Plus: Only draft requests can be submitted.')
        if not self.justification:
            raise UserError(
                'OdoSec Plus: A business justification is required before submitting.'
            )
        self.write({'state': 'pending'})
        self._notify_system_admins()
        return True

    # ── Transition: Approve ───────────────────────────────────────────────────
    def action_approve(self):
        self.ensure_one()
        self._require_system_admin()
        if self.state != 'pending':
            raise UserError('OdoSec Plus: Only pending requests can be approved.')
        self.write({
            'state':         'approved',
            'approved_by':   self.env.uid,
            'decision_date': fields.Datetime.now(),
        })
        self._execute_deletion()
        return True

    # ── Transition: Reject ────────────────────────────────────────────────────
    def action_reject(self):
        self.ensure_one()
        self._require_system_admin()
        if self.state not in ('pending', 'draft'):
            raise UserError('OdoSec Plus: Cannot reject in current state.')
        self.write({
            'state':         'rejected',
            'approved_by':   self.env.uid,
            'decision_date': fields.Datetime.now(),
        })
        self.message_post(
            body=f'Deletion request <b>{self.name}</b> has been '
                 f'<span style="color:red">REJECTED</span>.',
            subtype_xmlid='mail.mt_note',
        )
        return True

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _require_system_admin(self):
        if not self.env.user.has_group('base.group_system'):
            raise AccessError(
                'OdoSec Plus: Only System Administrators can approve '
                'or reject deletion requests.'
            )

    def _notify_system_admins(self):
        admins = self.env['res.users'].search([
            ('groups_id.id', '=', self.env.ref('base.group_system').id),
            ('active', '=', True),
        ])
        partner_ids = admins.mapped('partner_id').ids
        self.message_post(
            body=(
                f'<b>Deletion Request Submitted</b><br/>'
                f'Model: <code>{self.model_name}</code><br/>'
                f'Record ID: <b>{self.record_id}</b><br/>'
                f'Requested by: {self.requested_by.name}<br/>'
                f'Justification: {self.justification or "(Auto-generated)"}'
            ),
            partner_ids=partner_ids,
            subtype_xmlid='mail.mt_comment',
        )

    def _execute_deletion(self):
        """
        Perform the physical record deletion.
        Uses '_odosec_deletion_approved' context to bypass the deletion mixin guard.
        Also emits an audit log entry for the actual unlink.
        """
        try:
            record = self.env[self.model_name].sudo().browse(self.record_id)
            if record.exists():
                record.sudo().with_context(_odosec_deletion_approved=True).unlink()
                ts = fields.Datetime.now()
                self.env['odosec.audit.log'].sudo().create({
                    'user_id':     self.approved_by.id,
                    'model_name':  self.model_name,
                    'record_id':   self.record_id,
                    'action_type': 'unlink',
                    'additional_info': (
                        f'Governed deletion executed. '
                        f'Request: {self.name}. '
                        f'Approved by: {self.approved_by.name}'
                    ),
                    'timestamp': ts,
                    'tamper_hash': self.env['odosec.audit.log']._build_hash(
                        self.approved_by.id, self.model_name, self.record_id,
                        'unlink', fields.Datetime.to_string(ts),
                    ),
                })
                self.message_post(
                    body=(
                        f'✅ Deletion of <code>{self.model_name}</code> '
                        f'ID={self.record_id} executed successfully.'
                    ),
                    subtype_xmlid='mail.mt_note',
                )
            else:
                self.message_post(
                    body=f'⚠️ Record {self.model_name}#{self.record_id} '
                         f'no longer exists — nothing to delete.',
                    subtype_xmlid='mail.mt_note',
                )
        except Exception as exc:
            self.message_post(
                body=f'❌ Deletion failed: {exc}',
                subtype_xmlid='mail.mt_note',
            )
            raise UserError(f'OdoSec Plus: Deletion execution failed — {exc}') from exc
