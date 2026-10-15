# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import hashlib
from typing import cast

from verifier.verifications.tdx import IntelResult, check_report_data


def _make_intel_result(report_data: bytes) -> IntelResult:
    return cast(
        IntelResult,
        {
            "quote": {
                "body": {
                    "reportdata": report_data.hex(),
                    "mrconfig": "",
                }
            },
            "verified": True,
        },
    )


def test_check_report_data_without_tls_fingerprint_binds_address() -> None:
    signing_address = "0x" + "11" * 20
    signing_bytes = bytes.fromhex("11" * 20)
    nonce_bytes = bytes.fromhex("22" * 32)
    report_data = signing_bytes.ljust(32, b"\x00") + nonce_bytes

    attestation = {
        "signing_address": signing_address,
        "signing_algo": "ecdsa",
    }
    result = check_report_data(
        attestation, nonce_bytes.hex(), _make_intel_result(report_data)
    )

    assert result["binds_address"] is True
    assert result.get("binds_tls_cert", False) is False
    assert result["embeds_nonce"] is True


def test_check_report_data_rejects_mismatched_nonce() -> None:
    """A quote whose report_data embeds a different nonce must not pass."""
    signing_bytes = bytes.fromhex("11" * 20)
    embedded_nonce = bytes.fromhex("22" * 32)
    requested_nonce = bytes.fromhex("33" * 32)
    report_data = signing_bytes.ljust(32, b"\x00") + embedded_nonce

    attestation = {
        "signing_address": "0x" + "11" * 20,
        "signing_algo": "ecdsa",
    }
    result = check_report_data(
        attestation, requested_nonce.hex(), _make_intel_result(report_data)
    )

    assert result["embeds_nonce"] is False
    # The identity binding is unaffected; only freshness failed.
    assert result["binds_address"] is True


def test_check_report_data_with_tls_fingerprint_uses_hashed_binding() -> None:
    signing_address = "0x" + "aa" * 20
    signing_bytes = bytes.fromhex("aa" * 20)
    nonce_bytes = bytes.fromhex("bb" * 32)
    fingerprint_bytes = bytes.fromhex("cc" * 32)

    hashed_binding = hashlib.sha256(signing_bytes + fingerprint_bytes).digest()
    report_data = hashed_binding + nonce_bytes

    attestation = {
        "signing_address": signing_address,
        "signing_algo": "ecdsa",
        "tls_cert_fingerprint": fingerprint_bytes.hex(),
    }

    result = check_report_data(
        attestation, nonce_bytes.hex(), _make_intel_result(report_data)
    )

    assert result["binds_address"] is False
    assert result.get("binds_tls_cert", False) is True
    assert result["embeds_nonce"] is True


def test_null_app_compose_is_absent() -> None:
    from verifier.verifications.tdx import _extract_app_compose

    attestation = {"info": {"tcb_info": {"app_compose": None}}}
    assert _extract_app_compose(attestation) == ""
