# -*- coding: utf-8 -*-
"""
OdoSec Plus — Encryption Service
===================================
Manages Fernet (AES-128-CBC + HMAC-SHA256) symmetric encryption.
The encryption key is stored in ir.config_parameter and is auto-generated
on first use. Key rotation support included.
"""
from cryptography.fernet import Fernet, MultiFernet


class EncryptionService:
    """
    Thin wrapper around the cryptography Fernet implementation.

    Key storage: Odoo system parameter 'odosec.backup_fernet_key'
    Key rotation: Multiple keys supported via MultiFernet (newest first).
    """

    PARAM_KEY = 'odosec.backup_fernet_key'

    def __init__(self, env):
        self._env = env

    def _get_fernet(self) -> MultiFernet:
        """
        Load the current encryption key from ir.config_parameter.
        Auto-generates a new key if none exists.
        Returns a MultiFernet to support key rotation.
        """
        param  = self._env['ir.config_parameter'].sudo()
        stored = param.get_param(self.PARAM_KEY)

        if not stored:
            # First-time setup: generate a new random key
            new_key = Fernet.generate_key().decode('utf-8')
            param.set_param(self.PARAM_KEY, new_key)
            stored = new_key

        # Support comma-separated list for key rotation (newest first)
        keys = [k.strip().encode('utf-8') for k in stored.split(',') if k.strip()]
        fernets = [Fernet(k) for k in keys]
        return MultiFernet(fernets)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt raw bytes. Returns Fernet token."""
        return self._get_fernet().encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt a Fernet token. Raises InvalidToken if key mismatch."""
        return self._get_fernet().decrypt(token)

    def rotate_key(self) -> str:
        """
        Generate a new encryption key and prepend it to the stored key list.
        Returns the new key string.
        Old key is retained for decryption of previously encrypted backups.
        """
        param   = self._env['ir.config_parameter'].sudo()
        stored  = param.get_param(self.PARAM_KEY, '')
        new_key = Fernet.generate_key().decode('utf-8')
        # Prepend new key; keep up to 3 keys for rotation compatibility
        key_list = [new_key] + [k for k in stored.split(',') if k.strip()][:2]
        param.set_param(self.PARAM_KEY, ','.join(key_list))
        return new_key
