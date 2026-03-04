# -*- coding: utf-8 -*-
{
    'name': 'OdoSec Plus',
    'version': '19.0.1.0.0',
    'summary': 'Enterprise Auditing, Backup, Deletion Governance & Security Hardening',
    'description': '''
        OdoSec Plus — Enterprise-Grade Odoo Security Module
        ====================================================
        ✔ Tamper-resistant, write-once audit trail for all ORM operations
        ✔ Encrypted database backup with one-click UI download
        ✔ Deletion governance workflow: Draft → Pending → Approved / Rejected
        ✔ Automated vulnerability scanner (ACLs, record rules, model exposure)
        ✔ IP allowlist/blocklist with CIDR support
        ✔ Login rate-limiter with automatic lockout
        ✔ Security Health Dashboard with risk scoring
        ✔ RBAC with three escalating roles (Viewer / Analyst / Administrator)

        Supported: Odoo 19.0 CE & EE
        Tested on: Python 3.11 / 3.12 / PostgreSQL 15+
    ''',
    'author': 'OdoSec Team',
    'website': 'https://odosec.io',
    'category': 'Technical/Security',
    'license': 'LGPL-3',

    'depends': [
        'base',
        'mail',
        'web',
        'base_setup',
        'auth_signup',
    ],

    'external_dependencies': {
        'python': ['cryptography'],
    },

    'data': [
        'security/security_groups.xml',
        'security/ir.model.access.csv',
        'security/record_rules.xml',
        'data/ir_sequence_data.xml',
        'data/ir_cron_data.xml',
        'views/audit_log_views.xml',
        'views/backup_views.xml',
        'views/deletion_request_views.xml',
        'views/security_scan_views.xml',
        'views/security_health_views.xml',
        'views/menu_views.xml',
        'wizards/deletion_approval_wizard_views.xml',
    ],

    'assets': {
        'web.assets_backend': [
            'odosec_plus/static/src/css/odosec.css',
        ],
    },

    'images': ['static/description/icon.png'],
    'installable': True,
    'application': True,
    'auto_install': False,
}
