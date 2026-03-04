# -*- coding: utf-8 -*-
"""OdoSec Plus — IP Allowlist / Blocklist"""
import ipaddress
from odoo import models, fields, api
from odoo.exceptions import AccessError, ValidationError


class OdooSecIPRestriction(models.Model):
    _name        = 'odosec.ip.restriction'
    _description = 'OdoSec Plus — IP Restriction Rule'
    _order       = 'sequence asc, id asc'
    _rec_name    = 'name'

    name        = fields.Char(string='Rule Name', required=True)
    sequence    = fields.Integer(string='Priority', default=10,
                      help='Lower sequence = higher priority. Evaluated in order.')
    ip_range    = fields.Char(
        string='IP / CIDR Range', required=True,
        help='Examples: 192.168.1.100  /  10.0.0.0/8  /  2001:db8::/32',
    )
    rule_type   = fields.Selection([
        ('allow', 'Allow'),
        ('block', 'Block'),
    ], string='Rule Type', required=True, default='block')
    scope       = fields.Selection([
        ('all',   'All Users'),
        ('group', 'Specific Groups'),
        ('users', 'Specific Users'),
    ], default='all', string='Scope')
    group_ids   = fields.Many2many(
        'res.groups', string='Apply to Groups',
        help='Only relevant when Scope = Specific Groups.',
    )
    user_ids    = fields.Many2many(
        'res.users', string='Apply to Users',
        help='Only relevant when Scope = Specific Users.',
    )
    active      = fields.Boolean(default=True)
    notes       = fields.Text(string='Notes')

    # ── Validation ────────────────────────────────────────────────────────────
    @api.constrains('ip_range')
    def _check_ip_range(self):
        for rec in self:
            try:
                ipaddress.ip_network(rec.ip_range.strip(), strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(rec.ip_range.strip())
                except ValueError:
                    raise ValidationError(
                        f'OdoSec Plus: "{rec.ip_range}" is not a valid IP address or CIDR range.'
                    )

    # ── Class-level IP check ──────────────────────────────────────────────────
    @api.model
    def check_ip(self, ip_str, user_id=None, group_ids=None):
        """
        Check an IP address against active rules.
        Rules are evaluated in sequence order.
        First matching rule wins.

        Raises AccessError if the IP is blocked.
        Returns True if explicitly allowed.
        Returns None if no rule matched (default: allow).
        """
        if not ip_str:
            return None
        try:
            client_ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return None

        rules = self.sudo().search([('active', '=', True)], order='sequence asc')
        for rule in rules:
            # Scope filtering
            if rule.scope == 'users' and user_id:
                if user_id not in rule.user_ids.ids:
                    continue
            elif rule.scope == 'group' and group_ids:
                if not (set(group_ids) & set(rule.group_ids.ids)):
                    continue

            # IP matching
            try:
                network = ipaddress.ip_network(rule.ip_range.strip(), strict=False)
                if client_ip in network:
                    if rule.rule_type == 'block':
                        raise AccessError(
                            f'OdoSec Plus: Access from IP {ip_str} is blocked '
                            f'by rule "{rule.name}".'
                        )
                    return True  # explicitly allowed
            except ValueError:
                continue

        return None  # No rule matched; default allow
