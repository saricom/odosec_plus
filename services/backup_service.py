# -*- coding: utf-8 -*-
"""
OdoSec Plus — Backup Service
==============================
Orchestrates: pg_dump → GZIP compress → Fernet encrypt → write to disk.

Security measures:
  - pg_dump executed via subprocess, NOT shell=True
  - PGPASSWORD injected into subprocess env, never logged
  - Output file permissions set to 0o600 (owner read-only)
  - Backup directory created with 0o700
  - Path validated before writing (no traversal)
"""
import os
import gzip
import subprocess
import tempfile

from odoo.tools import config
from .encryption_service import EncryptionService


class BackupService:

    DEFAULT_BACKUP_DIR = '/var/odoo/odosec_backups'
    SUBPROCESS_TIMEOUT = 3600   # 1 hour max for pg_dump

    def __init__(self, env):
        self._env = env
        self._enc = EncryptionService(env)
        self._backup_dir = config.get(
            'odosec_backup_dir', self.DEFAULT_BACKUP_DIR
        )
        # Ensure backup directory exists with restricted permissions
        os.makedirs(self._backup_dir, mode=0o700, exist_ok=True)

    def create_encrypted_backup(self, backup_name: str) -> tuple:
        """
        Full pipeline: dump → compress → encrypt → persist.

        Args:
            backup_name: Base filename (no extension) for the output file.

        Returns:
            (file_path: str, size_mb: float)

        Raises:
            RuntimeError: if pg_dump fails.
            OSError: if file I/O fails.
        """
        # ── Resolve database connection params ─────────────────────────────
        db_name = config['db_name']
        db_host = config.get('db_host', 'localhost') or 'localhost'
        db_port = str(config.get('db_port', '5432') or '5432')
        db_user = config.get('db_user', 'odoo') or 'odoo'
        db_pass = config.get('db_password', '') or ''

        # ── Validate output path ───────────────────────────────────────────
        out_filename = f'{backup_name}.sql.gz.enc'
        out_path = os.path.realpath(
            os.path.join(self._backup_dir, out_filename)
        )
        real_dir = os.path.realpath(self._backup_dir)
        if not out_path.startswith(real_dir + os.sep):
            raise ValueError(
                f'OdoSec Plus: Backup path traversal detected: {out_path}'
            )

        # ── Step 1: pg_dump to a temporary file ───────────────────────────
        with tempfile.NamedTemporaryFile(
            suffix='.sql', prefix='odosec_tmp_', delete=False
        ) as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                'pg_dump',
                '--format=plain',
                '--no-password',
                '-h', db_host,
                '-p', db_port,
                '-U', db_user,
                '-d', db_name,
                '-f', tmp_path,
            ]
            env_vars = dict(os.environ)
            if db_pass:
                env_vars['PGPASSWORD'] = db_pass

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.SUBPROCESS_TIMEOUT,
                env=env_vars,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f'pg_dump exited with code {result.returncode}: '
                    f'{result.stderr[:500]}'
                )

            # ── Step 2: Read raw SQL and GZIP compress ──────────────────
            with open(tmp_path, 'rb') as f:
                raw_bytes = f.read()
        finally:
            # Always remove temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        if not raw_bytes:
            raise RuntimeError('OdoSec Plus: pg_dump produced empty output.')

        gz_bytes = gzip.compress(raw_bytes, compresslevel=6)
        del raw_bytes  # free memory early

        # ── Step 3: Fernet encrypt ────────────────────────────────────────
        encrypted = self._enc.encrypt(gz_bytes)
        del gz_bytes

        # ── Step 4: Write encrypted file ──────────────────────────────────
        with open(out_path, 'wb') as f:
            f.write(encrypted)
        os.chmod(out_path, 0o600)

        size_mb = round(len(encrypted) / (1024 * 1024), 2)
        del encrypted

        return out_path, size_mb

    def decrypt_backup(self, file_path: str) -> bytes:
        """
        Decrypt an encrypted backup file and return the raw GZIP bytes.
        The caller is responsible for decompressing and applying the SQL dump.
        """
        real_path = os.path.realpath(file_path)
        real_dir  = os.path.realpath(self._backup_dir)
        if not real_path.startswith(real_dir + os.sep):
            raise ValueError('OdoSec Plus: Path traversal detected.')
        if not os.path.isfile(real_path):
            raise FileNotFoundError(f'Backup file not found: {real_path}')

        with open(real_path, 'rb') as f:
            encrypted = f.read()

        return self._enc.decrypt(encrypted)
