from __future__ import annotations

import base64
import ctypes
import sys
from ctypes import wintypes


class SecretStoreError(RuntimeError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class WindowsDpapiSecretStore:
    """Protect secrets for the current Windows user with DPAPI."""

    PREFIX = "dpapi:"
    _UI_FORBIDDEN = 0x01

    def protect(self, secret: str) -> str:
        if not secret:
            raise SecretStoreError("API key cannot be empty.")
        protected = self._crypt(secret.encode("utf-8"), decrypt=False)
        return f"{self.PREFIX}{base64.b64encode(protected).decode('ascii')}"

    def unprotect(self, protected_secret: str) -> str:
        if not protected_secret.startswith(self.PREFIX):
            raise SecretStoreError("The stored API key is not in a supported protected format.")
        try:
            payload = base64.b64decode(protected_secret.removeprefix(self.PREFIX), validate=True)
        except ValueError as exc:
            raise SecretStoreError("The stored API key is corrupted.") from exc
        try:
            return self._crypt(payload, decrypt=True).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecretStoreError("The stored API key is corrupted.") from exc

    def _crypt(self, payload: bytes, *, decrypt: bool) -> bytes:
        if sys.platform != "win32":
            raise SecretStoreError("Secure API key storage is currently available on Windows only.")

        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        source_buffer = ctypes.create_string_buffer(payload)
        source = _DataBlob(len(payload), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        destination = _DataBlob()

        function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
        if decrypt:
            success = function(
                ctypes.byref(source),
                None,
                None,
                None,
                None,
                self._UI_FORBIDDEN,
                ctypes.byref(destination),
            )
        else:
            success = function(
                ctypes.byref(source),
                "Lightweight IDS LLM API key",
                None,
                None,
                None,
                self._UI_FORBIDDEN,
                ctypes.byref(destination),
            )
        if not success:
            error = ctypes.get_last_error()
            raise SecretStoreError(f"Windows could not protect the API key: {ctypes.FormatError(error)}")
        try:
            return ctypes.string_at(destination.pbData, destination.cbData)
        finally:
            kernel32.LocalFree(destination.pbData)
