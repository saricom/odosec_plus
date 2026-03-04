# -*- coding: utf-8 -*-
"""
OdoSec Plus — Deletion Approval Wizard
========================================
A transient wizard used by System Administrators to approve or reject
pending deletion requests, optionally adding a decision note.
"""
from odoo import models, fields, api
from odoo.exceptions import AccessError, UserError


class OdooSecDeletionApprovalWizard(models.TransientModel):
    _name        = 'odosec.deletion.approval.wizard'
    _description = 'OdoSec Plus — Deletion Approval Wizard'

    deletion_request_id = fields.Many2one(
        'odosec.deletion.request', string='Deletion Request',
        required=True, readonly=True,
    )
    model_name     = fields.Char(related='deletion_request_id.model_name', readonly=True)
    record_id      = fields.Integer(related='deletion_request_id.record_id', readonly=True)
    record_repr    = fields.Text(related='deletion_request_id.record_repr', readonly=True)
    justification  = fields.Text(related='deletion_request_id.justification', readonly=True)
    decision_note  = fields.Text(string='Decision Note (optional)')
    decision       = fields.Selection([
        ('approve', 'Approve — Delete the Record'),
        ('reject',  'Reject — Keep the Record'),
    ], string='Decision', required=True, default='reject')

    @api.model
    def default_get(self, fields_list):
        res = super().default_get(fields_list)
        if not self.env.user.has_group('base.group_system'):
            raise AccessError(
                'OdoSec Plus: Only System Administrators can process deletion requests.'
            )
        active_id = self.env.context.get('active_id')
        if active_id:
            res['deletion_request_id'] = active_id
        return res

    def action_confirm(self):
        self.ensure_one()
        if not self.env.user.has_group('base.group_system'):
            raise AccessError('OdoSec Plus: Insufficient permissions.')

        req = self.deletion_request_id
        if req.state != 'pending':
            raise UserError(
                'OdoSec Plus: This request is no longer pending approval.'
            )
        if self.decision_note:
            req.decision_note = self.decision_note

        if self.decision == 'approve':
            req.action_approve()
            msg = (
                f'✅ Deletion request {req.name} approved. '
                f'Record {req.model_name}#{req.record_id} has been deleted.'
            )
        else:
            req.action_reject()
            msg = f'❌ Deletion request {req.name} rejected.'

        return {
            'type': 'ir.actions.client',
            'tag':  'display_notification',
            'params': {
                'title':   'Decision Recorded',
                'message': msg,
                'type':    'success' if self.decision == 'reject' else 'warning',
                'sticky':  False,
            },
        }
