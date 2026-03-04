# -*- coding: utf-8 -*-
"""
OdoSec Plus — Automated Security Scanner
==========================================
Scans Odoo's metadata (ACLs, record rules, model registry) for
security misconfigurations and generates odosec.scan.finding records.
"""
from odoo import models, fields, api
from odoo.exceptions import AccessError


class OdooSecSecurityScan(models.Model):
    _name        = 'odosec.security.scan'
    _description = 'OdoSec Plus — Security Scan'
    _order       = 'scan_date desc'
    _rec_name    = 'display_ref'

    # ── Fields ────────────────────────────────────────────────────────────────
    scan_date      = fields.Datetime(
        string='Scan Date', readonly=True, default=fields.Datetime.now,
    )
    scan_type      = fields.Selection([
        ('acl',         'ACL & Permissions Scan'),
        ('record_rule', 'Record Rule Scan'),
        ('model',       'Model Exposure Scan'),
        ('full',        'Full Security Scan'),
    ], default='full', required=True, string='Scan Type')
    state          = fields.Selection([
        ('running', 'Running'),
        ('done',    'Completed'),
        ('error',   'Error'),
    ], default='running', readonly=True, string='Status', index=True)
    triggered_by   = fields.Many2one(
        'res.users', readonly=True, default=lambda s: s.env.uid,
    )
    finding_ids    = fields.One2many(
        'odosec.scan.finding', 'scan_id', string='Findings', readonly=True,
    )
    critical_count = fields.Integer(compute='_compute_counts', string='Critical', store=True)
    high_count     = fields.Integer(compute='_compute_counts', string='High', store=True)
    medium_count   = fields.Integer(compute='_compute_counts', string='Medium', store=True)
    low_count      = fields.Integer(compute='_compute_counts', string='Low', store=True)
    total_findings = fields.Integer(compute='_compute_counts', string='Total', store=True)
    risk_score     = fields.Integer(compute='_compute_risk_score', string='Risk Score', store=True)
    display_ref    = fields.Char(compute='_compute_display_ref', store=True)
    duration_sec   = fields.Float(string='Duration (s)', readonly=True)
    error_msg      = fields.Text(string='Error', readonly=True)

    # ── Computed ──────────────────────────────────────────────────────────────
    @api.depends('finding_ids.severity', 'finding_ids.is_resolved')
    def _compute_counts(self):
        for rec in self:
            active = rec.finding_ids.filtered(lambda f: not f.is_resolved)
            rec.critical_count = len(active.filtered(lambda f: f.severity == 'critical'))
            rec.high_count     = len(active.filtered(lambda f: f.severity == 'high'))
            rec.medium_count   = len(active.filtered(lambda f: f.severity == 'medium'))
            rec.low_count      = len(active.filtered(lambda f: f.severity == 'low'))
            rec.total_findings = len(active)

    @api.depends('critical_count', 'high_count', 'medium_count', 'low_count')
    def _compute_risk_score(self):
        for rec in self:
            rec.risk_score = (
                rec.critical_count * 10 +
                rec.high_count     * 5  +
                rec.medium_count   * 2  +
                rec.low_count      * 1
            )

    @api.depends('scan_date', 'scan_type')
    def _compute_display_ref(self):
        type_labels = {
            'acl': 'ACL', 'record_rule': 'Rules',
            'model': 'Models', 'full': 'Full',
        }
        for rec in self:
            lbl = type_labels.get(rec.scan_type or 'full', 'Scan')
            ts  = fields.Datetime.to_string(rec.scan_date)[:16] if rec.scan_date else '?'
            rec.display_ref = f'SCAN-{lbl.upper()}/{ts}'

    # ── Main action ───────────────────────────────────────────────────────────
    @api.model
    def action_run_scan(self, scan_type='full'):
        """
        Create and execute a new scan. Returns the created scan record.
        Requires at minimum OdoSec Analyst role.
        """
        if not self.env.user.has_group('odosec_plus.group_odosec_analyst'):
            raise AccessError(
                'OdoSec Plus: Security scans require at least OdoSec Analyst role.'
            )
        import time
        scan = self.create({'scan_type': scan_type, 'state': 'running'})
        scan.flush_model()
        t0 = time.monotonic()
        try:
            if scan_type in ('acl', 'full'):
                scan._run_acl_scan()
            if scan_type in ('record_rule', 'full'):
                scan._run_record_rule_scan()
            if scan_type in ('model', 'full'):
                scan._run_model_exposure_scan()
            if scan_type == 'full':
                scan._run_config_scan()
            elapsed = round(time.monotonic() - t0, 2)
            scan.write({'state': 'done', 'duration_sec': elapsed})
        except Exception as exc:
            scan.write({'state': 'error', 'error_msg': str(exc)})
            raise
        return scan

    @api.model
    def action_run_scheduled_scan(self):
        """Entry point for the scheduled cron job."""
        return self.action_run_scan(scan_type='full')

    # ── Scan engines ─────────────────────────────────────────────────────────

    def _run_acl_scan(self):
        """Detect overly permissive ACLs."""
        public_group = self.env.ref('base.group_public', raise_if_not_found=False)
        portal_group = self.env.ref('base.group_portal', raise_if_not_found=False)

        acls = self.env['ir.model.access'].sudo().search([])
        for acl in acls:
            # Public group with write/create/delete permissions
            if public_group and acl.group_id == public_group:
                if acl.perm_write or acl.perm_unlink or acl.perm_create:
                    self._create_finding(
                        severity='critical', category='acl',
                        title=f'Public group has write/delete access on {acl.model_id.model}',
                        detail=(
                            f'ACL record "{acl.name}" (id={acl.id}) grants '
                            f'create={acl.perm_create}, write={acl.perm_write}, '
                            f'delete={acl.perm_unlink} to the public group.'
                        ),
                        remediation='Remove write/create/delete from public-facing ACLs immediately.',
                        ref=acl.model_id.model,
                    )
            # Portal group with delete permissions
            if portal_group and acl.group_id == portal_group:
                if acl.perm_unlink:
                    self._create_finding(
                        severity='high', category='acl',
                        title=f'Portal group can delete records in {acl.model_id.model}',
                        detail=f'ACL id={acl.id}: portal users have unlink permission.',
                        remediation='Remove delete permission from portal ACL.',
                        ref=acl.model_id.model,
                    )
            # ACLs with no group (applies to ALL users including public)
            if not acl.group_id:
                if acl.perm_write or acl.perm_unlink or acl.perm_create:
                    self._create_finding(
                        severity='high', category='acl',
                        title=f'Global (no group) ACL with write access on {acl.model_id.model}',
                        detail=(
                            f'ACL "{acl.name}" has no group restriction. '
                            f'It grants write={acl.perm_write}, unlink={acl.perm_unlink}.'
                        ),
                        remediation='Assign a specific group to this ACL.',
                        ref=acl.model_id.model,
                    )

    def _run_record_rule_scan(self):
        """Detect record rules with dangerous domain patterns."""
        rules = self.env['ir.rule'].sudo().search([('active', '=', True)])
        DANGEROUS_DOMAINS = ['(1, =, 1)', "[(1,'=',1)]", '[(1, =, 1)]']
        for rule in rules:
            domain_str = str(rule.domain_force or '')
            # Truly open domain: matches everything
            if any(d in domain_str for d in DANGEROUS_DOMAINS):
                severity = 'info'  # Can be intentional; flag for review
                self._create_finding(
                    severity=severity, category='record_rule',
                    title=f'Record rule "{rule.name}" uses open domain [(1,=,1)]',
                    detail=(
                        f'Rule id={rule.id} on model {rule.model_id.model} '
                        f'uses a domain that matches all records. This may be intentional '
                        f'but should be reviewed.'
                    ),
                    remediation='Verify whether the open domain is intentional. '
                                'Restrict to user-specific domain if possible.',
                    ref=rule.model_id.model,
                )
            # No group restriction on a write/delete rule
            if not rule.groups and (rule.perm_write or rule.perm_unlink):
                self._create_finding(
                    severity='medium', category='record_rule',
                    title=f'Record rule "{rule.name}" has no group and allows write/delete',
                    detail=(
                        f'Rule id={rule.id} applies to all users without group restriction '
                        f'and grants write/delete scope.'
                    ),
                    remediation='Assign the rule to a specific security group.',
                    ref=rule.model_id.model,
                )

    def _run_model_exposure_scan(self):
        """Detect models registered in Odoo with no ACL defined."""
        all_models    = self.env['ir.model'].sudo().search([])
        models_with_acl = set(
            self.env['ir.model.access'].sudo().search([]).mapped('model_id').ids
        )
        # Internal/abstract models that don't need ACLs
        SKIP_PREFIXES = ('ir.', 'base.', 'mail.', 'bus.', 'web.')
        for m in all_models:
            if m.id not in models_with_acl:
                if any(m.model.startswith(p) for p in SKIP_PREFIXES):
                    continue
                self._create_finding(
                    severity='high', category='model',
                    title=f'Model {m.model} has no ACL defined',
                    detail=(
                        f'Model "{m.name}" ({m.model}) has no ir.model.access entries. '
                        f'Authenticated users may access it via JSON-RPC.'
                    ),
                    remediation='Add ir.model.access.csv entries for this model.',
                    ref=m.model,
                )

    def _run_config_scan(self):
        """Detect insecure system configuration parameters."""
        param = self.env['ir.config_parameter'].sudo()

        # Check if debug mode is enabled in production
        debug_url = param.get_param('web.base.url', '')
        if 'debug=' in str(debug_url):
            self._create_finding(
                severity='medium', category='config',
                title='Debug mode appears active in base URL',
                detail=f'web.base.url contains "debug=": {debug_url}',
                remediation='Remove debug parameter from web.base.url in system parameters.',
            )

        # Check if signup is open (anyone can register)
        signup_enabled = param.get_param('auth_signup.invitation_scope', 'b2b')
        if signup_enabled == 'b2c':
            self._create_finding(
                severity='medium', category='config',
                title='Public user self-registration is enabled',
                detail='auth_signup.invitation_scope = b2c allows anyone to register.',
                remediation='Set to "b2b" unless public registration is intentional.',
            )

        # Check if password reset is unrestricted
        reset_policy = param.get_param('auth_signup.reset_password', 'False')
        if str(reset_policy).lower() == 'true':
            self._create_finding(
                severity='low', category='config',
                title='Password reset via email is enabled',
                detail='Users can reset passwords without admin approval.',
                remediation='Review whether self-service password reset is appropriate.',
            )

    # ── Internal helper ───────────────────────────────────────────────────────
    def _create_finding(self, severity, category, title,
                        detail='', remediation='', ref=''):
        self.env['odosec.scan.finding'].sudo().create({
            'scan_id':      self.id,
            'severity':     severity,
            'category':     category,
            'title':        title,
            'detail':       detail,
            'remediation':  remediation,
            'affected_ref': ref,
        })
