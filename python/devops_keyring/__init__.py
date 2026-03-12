"""Keyring backend for Azure DevOps feeds using browser-based OAuth2."""

import keyring.backend
import keyring.credentials

from . import _native


class DevOpsKeyring(keyring.backend.KeyringBackend):
    """Authenticates to Azure DevOps package feeds via browser OAuth2 + PKCE.

    Works on WSL, Linux, and macOS. Tokens are cached to avoid repeated prompts.
    """

    priority = 10  # Higher than artifacts-keyring (9.9)

    def get_password(self, service, username):
        result = _native.authenticate(service)
        if result:
            return result[1]
        return None

    def get_credential(self, service, username):
        result = _native.authenticate(service)
        if result:
            return keyring.credentials.SimpleCredential(result[0], result[1])
        return None

    def set_password(self, service, username, password):
        raise NotImplementedError("devops-keyring is read-only")

    def delete_password(self, service, username):
        raise NotImplementedError("devops-keyring is read-only")
