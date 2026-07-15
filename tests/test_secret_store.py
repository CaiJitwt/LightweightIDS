from __future__ import annotations

import sys

import pytest

from modern_ui.secret_store import WindowsDpapiSecretStore


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI is Windows-only")
def test_windows_dpapi_secret_store_round_trip_without_plaintext():
    store = WindowsDpapiSecretStore()

    protected = store.protect("temporary-api-key")

    assert protected.startswith("dpapi:")
    assert "temporary-api-key" not in protected
    assert store.unprotect(protected) == "temporary-api-key"
