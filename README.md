# OdoSec Plus — Enterprise Odoo Security Module

## Version Compatibility
| Module Version | Odoo Target |
|---|---|
| 17.0.1.0.0 | Odoo 17.0 CE & EE |

> **Note:** Odoo 19 has not been released as of this build (latest stable: Odoo 17). This module
> is built on Odoo 17 APIs with forward-compatible patterns (Odoo 18+ may require minor adaptation).

## Installation

### Prerequisites
```bash
pip install cryptography>=41.0
```
Ensure `pg_dump` is accessible in the Odoo server `PATH`.

### Install Steps
1. Copy `odosec_plus/` directory into your Odoo addons path
2. Restart Odoo server
3. Activate Developer Mode
4. Go to Apps → Update Apps List
5. Search "OdoSec Plus" and click Install

### Configuration (odoo.conf)
```ini
# Optional: specify backup directory (default: /var/odoo/odosec_backups)
odosec_backup_dir = /your/secure/backup/path
```

## Module Structure
```
odosec_plus/
├── controllers/       # HTTP routes (backup download, health probe)
├── data/              # Sequences, cron jobs
├── models/            # ORM models (audit, backup, deletion, scan, health, IP, rate-limit)
├── security/          # ACLs, record rules, security groups
├── services/          # BackupService, EncryptionService
├── static/            # CSS assets
├── views/             # XML views for all models
└── wizards/           # Deletion approval wizard
```

## Security Roles
| Role | Description |
|---|---|
| OdoSec Viewer | Read-only: audit logs, scan results, dashboard |
| OdoSec Analyst | Viewer + run scans, create deletion requests |
| OdoSec Administrator | Analyst + trigger backups, approve deletions, manage IP rules |
| System Administrator (Odoo built-in) | Full access including backup download |

## Key System Parameters
| Parameter | Default | Description |
|---|---|---|
| `odosec.backup_fernet_key` | Auto-generated | Fernet encryption key for backups |
| `odosec.log_retention_days` | 365 | Days to keep audit logs |
| `odosec.backup_retention_days` | 30 | Days to keep backup files on disk |

## Adding Audit Tracking to Custom Models
```python
class YourModel(models.Model):
    _name   = 'your.model'
    _inherit = ['your.model', 'odosec.audit.mixin']

    # Optional: restrict writable fields (mass-assignment guard)
    _odosec_writable_fields = ['name', 'description', 'state']

    # Optional: flag sensitive fields for special audit annotation
    _odosec_sensitive_fields = ['credit_limit', 'bank_account']
```

## Adding Deletion Governance to Custom Models
```python
# 1. Add to GOVERNED_MODELS in audit_mixin.py
# 2. Inherit the mixin:
class YourModel(models.Model):
    _name    = 'your.model'
    _inherit = ['your.model', 'odosec.deletion.mixin']
```
