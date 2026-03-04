# -*- coding: utf-8 -*-
"""OdoSec Plus — Security Health Dashboard Model"""
from odoo import models, fields, api


class OdooSecHealth(models.Model):
    _name        = 'odosec.security.health'
    _description = 'OdoSec Plus — Security Health Snapshot'
    _order       = 'computed_date desc'
    _rec_name    = 'computed_date'

    computed_date    = fields.Datetime(string='Computed At', readonly=True,
                           default=fields.Datetime.now)
    overall_risk     = fields.Selection([
        ('low',      'Low ✅'),
        ('medium',   'Medium ⚠️'),
        ('high',     'High 🔴'),
        ('critical', 'Critical 🚨'),
    ], string='Overall Risk', readonly=True, index=True)
    risk_score       = fields.Integer(string='Risk Score', readonly=True)

    # ── Audit metrics ─────────────────────────────────────────────────────────
    failed_logins_1h  = fields.Integer(string='Failed Logins (1h)', readonly=True)
    failed_logins_24h = fields.Integer(string='Failed Logins (24h)', readonly=True)
    total_logs_today  = fields.Integer(string='Total Events Today', readonly=True)

    # ── Scan metrics ──────────────────────────────────────────────────────────
    last_scan_id      = fields.Many2one('odosec.security.scan', string='Last Scan', readonly=True)
    open_critical     = fields.Integer(string='Open Critical Findings', readonly=True)
    open_high         = fields.Integer(string='Open High Findings', readonly=True)
    models_exposed    = fields.Integer(string='Models Without ACL', readonly=True)

    # ── Backup metrics ────────────────────────────────────────────────────────
    last_backup_date  = fields.Datetime(string='Last Successful Backup', readonly=True)
    backup_age_days   = fields.Integer(string='Backup Age (days)', readonly=True)
    backup_risk       = fields.Selection([
        ('ok',   'OK'), ('warn', 'Warning'), ('danger', 'Danger'),
    ], string='Backup Risk', readonly=True)

    # ── Deletion metrics ──────────────────────────────────────────────────────
    pending_deletions = fields.Integer(string='Pending Deletion Requests', readonly=True)

    # ── Locked accounts ───────────────────────────────────────────────────────
    locked_accounts   = fields.Integer(string='Locked Accounts', readonly=True)

    # ── Narrative summary ─────────────────────────────────────────────────────
    summary           = fields.Text(string='Risk Summary', readonly=True)

    # ── Compute & refresh ─────────────────────────────────────────────────────
    @api.model
    def action_compute_health(self):
        """Recompute all health metrics and create a new snapshot."""
        now          = fields.Datetime.now()
        one_hour_ago = fields.Datetime.subtract(now, hours=1)
        one_day_ago  = fields.Datetime.subtract(now, hours=24)
        today_start  = now.replace(hour=0, minute=0, second=0, microsecond=0)

        AuditLog  = self.env['odosec.audit.log'].sudo()
        Scan      = self.env['odosec.security.scan'].sudo()
        Backup    = self.env['odosec.backup.manager'].sudo()
        DelReq    = self.env['odosec.deletion.request'].sudo()
        RateLimit = self.env['odosec.rate.limiter'].sudo()

        # Audit metrics
        failed_1h  = AuditLog.search_count([
            ('action_type', '=', 'login_failed'),
            ('timestamp',   '>=', one_hour_ago),
        ])
        failed_24h = AuditLog.search_count([
            ('action_type', '=', 'login_failed'),
            ('timestamp',   '>=', one_day_ago),
        ])
        total_today = AuditLog.search_count([('timestamp', '>=', today_start)])

        # Last scan metrics
        last_scan = Scan.search([('state', '=', 'done')], order='scan_date desc', limit=1)
        open_crit  = 0
        open_high  = 0
        exposed    = 0
        scan_risk  = 0
        if last_scan:
            open_crit = last_scan.critical_count
            open_high = last_scan.high_count
            exposed = len(last_scan.finding_ids.filtered(
                lambda f: f.category == 'model' and not f.is_resolved
            ))
            scan_risk = last_scan.risk_score

        # Backup metrics
        last_backup = Backup.search([('state', '=', 'done')],
                                    order='create_date desc', limit=1)
        backup_date = last_backup.create_date if last_backup else False
        backup_age  = 0
        backup_risk = 'ok'
        if backup_date:
            backup_age = (now - backup_date).days
            if backup_age > 30:
                backup_risk = 'danger'
            elif backup_age > 7:
                backup_risk = 'warn'
        else:
            backup_risk = 'danger'
            backup_age  = 9999

        # Deletion & locked accounts
        pending_del = DelReq.search_count([('state', '=', 'pending')])
        locked      = RateLimit.search_count([('locked_until', '>', now)])

        # Compute combined risk score
        total_score = scan_risk
        if   failed_1h > 10: total_score += 15
        elif failed_1h > 5:  total_score += 8
        if backup_risk == 'danger': total_score += 10
        elif backup_risk == 'warn': total_score += 3
        if pending_del > 5: total_score += 5
        if locked > 0:      total_score += 3

        # Classify overall risk
        if   total_score >= 50: overall_risk = 'critical'
        elif total_score >= 25: overall_risk = 'high'
        elif total_score >= 10: overall_risk = 'medium'
        else:                   overall_risk = 'low'

        # Build narrative summary
        lines = [f'Risk Score: {total_score}  |  Level: {overall_risk.upper()}']
        if open_crit:             lines.append(f'⚠️  {open_crit} CRITICAL scan findings open')
        if open_high:             lines.append(f'⚠️  {open_high} HIGH scan findings open')
        if failed_1h > 5:         lines.append(f'🔒  {failed_1h} failed logins in last hour')
        if backup_risk == 'danger': lines.append(f'💾  No recent backup (age: {backup_age}d)')
        if pending_del:           lines.append(f'🗑️  {pending_del} deletion requests pending')
        if locked:                lines.append(f'🔐  {locked} accounts currently locked')

        return self.create({
            'computed_date':     now,
            'overall_risk':      overall_risk,
            'risk_score':        total_score,
            'failed_logins_1h':  failed_1h,
            'failed_logins_24h': failed_24h,
            'total_logs_today':  total_today,
            'last_scan_id':      last_scan.id if last_scan else False,
            'open_critical':     open_crit,
            'open_high':         open_high,
            'models_exposed':    exposed,
            'last_backup_date':  backup_date,
            'backup_age_days':   backup_age,
            'backup_risk':       backup_risk,
            'pending_deletions': pending_del,
            'locked_accounts':   locked,
            'summary':           '\n'.join(lines),
        })
