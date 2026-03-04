# -*- coding: utf-8 -*-
"""OdoSec Plus — Scan Finding (child of SecurityScan)"""
from odoo import models, fields, api


class OdooSecScanFinding(models.Model):
    _name        = 'odosec.scan.finding'
    _description = 'OdoSec Plus — Security Scan Finding'
    _order       = 'severity_order asc, id asc'
    _rec_name    = 'title'

    scan_id      = fields.Many2one(
        'odosec.security.scan', string='Scan', required=True,
        ondelete='cascade', index=True,
    )
    severity     = fields.Selection([
        ('critical', 'Critical'),
        ('high',     'High'),
        ('medium',   'Medium'),
        ('low',      'Low'),
        ('info',     'Info'),
    ], string='Severity', required=True, index=True)
    severity_order = fields.Integer(
        compute='_compute_severity_order', store=True,
        help='Numeric order for sorting (1=critical … 5=info)',
    )
    category     = fields.Selection([
        ('acl',         'ACL / Permissions'),
        ('record_rule', 'Record Rule'),
        ('controller',  'Controller / Route'),
        ('model',       'Model Exposure'),
        ('config',      'Configuration'),
        ('session',     'Session / Auth'),
    ], string='Category', required=True)
    title        = fields.Char(string='Finding', required=True)
    detail       = fields.Text(string='Technical Detail')
    remediation  = fields.Text(string='Recommended Remediation')
    affected_ref = fields.Char(string='Affected Object')
    is_resolved  = fields.Boolean(string='Marked Resolved', default=False)
    resolve_note = fields.Text(string='Resolution Note')

    @api.depends('severity')
    def _compute_severity_order(self):
        order_map = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        for rec in self:
            rec.severity_order = order_map.get(rec.severity, 99)

    def action_mark_resolved(self):
        self.write({'is_resolved': True})
