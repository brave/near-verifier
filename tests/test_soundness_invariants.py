# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fail-closed tests for the attestation-soundness invariants."""

import asyncio
import datetime
import hashlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse

import certifi
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from verifier.config import BASE_URL
from verifier.models import VerificationPolicy
from verifier.validation import _validate_domain_certificate
from verifier.verifications.compose_manager import _actions_report_data_hash
from verifier.verifications.tdx import (
    ACCEPTABLE_TDX_STATUSES,
    GatewayAttestationSummary,
    tdx_status_acceptable,
    verify_gateway_attestation,
)
from verifier.verifications.tls import (
    parse_certificate_chain,
    verify_certificate_key,
)

POLICY = VerificationPolicy(
    allowed_repos=[],
    allowed_builders=[],
    required_images=[],
    require_reproducible_build=True,
    skip_reproducibility_images=set(),
)

MOCK_INTEL_RESULT = {
    "quote": {"body": {"reportdata": "00" * 64, "mrconfig": "00" * 48}},
    "verified": True,
}

ISRG_NAME = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, "Internet Security Research Group"
        ),
        x509.NameAttribute(NameOID.COMMON_NAME, "ISRG Root X1"),
    ]
)

ATTACKER_NAME = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Totally Legit CA Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Totally Legit Root"),
    ]
)


def _self_signed_leaf(name: x509.Name) -> str:
    """A self-signed root with ``name`` and a cloud-api.near.ai leaf under it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    root = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cloud-api.near.ai")])
        )
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("cloud-api.near.ai")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return "".join(
        c.public_bytes(serialization.Encoding.PEM).decode() for c in (leaf, root)
    )


@pytest.mark.parametrize("name", [ATTACKER_NAME, ISRG_NAME], ids=["unknown", "forged"])
def test_untrusted_root_is_rejected(name: x509.Name) -> None:
    """A valid self-signature proves nothing, and neither does a trusted DN."""
    with pytest.raises(RuntimeError, match="Certificate verification failed"):
        verify_certificate_key(_self_signed_leaf(name), "cloud-api.near.ai")


def test_trust_store_holds_the_near_root() -> None:
    """ISRG Root X2, where the cloud-api.near.ai chain terminates, loads."""
    bundle = parse_certificate_chain(Path(certifi.where()).read_text())
    names = {
        a.value
        for c in bundle
        for a in c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    }
    assert "ISRG Root X2" in names


def test_outofdate_tdx_status_is_not_acceptable() -> None:
    assert "OutOfDate" not in ACCEPTABLE_TDX_STATUSES
    assert ACCEPTABLE_TDX_STATUSES == {"UpToDate", "SWHardeningNeeded"}


NEAR_ADVISORIES = [
    "INTEL-SA-01192",
    "INTEL-SA-01245",
    "INTEL-SA-01312",
    "INTEL-SA-01313",
]


@pytest.mark.parametrize(
    ("status", "advisories", "ok"),
    [
        ("UpToDate", [], True),
        ("SWHardeningNeeded", ["INTEL-SA-00001"], True),
        ("OutOfDate", NEAR_ADVISORIES, True),
        ("OutOfDate", NEAR_ADVISORIES[:2], True),
        ("OutOfDate", [*NEAR_ADVISORIES, "INTEL-SA-09999"], False),
        ("OutOfDate", [], False),
        ("OutOfDate", None, False),
        ("OutOfDateConfigurationNeeded", NEAR_ADVISORIES, False),
        ("Revoked", NEAR_ADVISORIES, False),
    ],
)
def test_outofdate_accepted_only_for_reviewed_advisories(
    status: str, advisories: list[str] | None, ok: bool
) -> None:
    assert tdx_status_acceptable(status, advisories) is ok


def _gateway_with_report_data(
    report_data: dict[str, bool],
) -> GatewayAttestationSummary:
    with (
        patch(
            "verifier.verifications.tdx.verify_tdx_quote",
            new=AsyncMock(return_value=MOCK_INTEL_RESULT),
        ),
        patch(
            "verifier.verifications.tdx.check_report_data",
            return_value=report_data,
        ),
        patch(
            "verifier.verifications.tdx.verify_source",
            return_value={"images": {}},
        ),
    ):
        return asyncio.run(verify_gateway_attestation({}, "nonce", POLICY))


def test_gateway_report_data_requires_tls_cert_binding() -> None:
    """Only binds_tls_cert anchors the quote to the client's channel;
    binds_address alone lets a gateway proxy a genuine backend's quote."""
    result = _gateway_with_report_data({"binds_address": True, "embeds_nonce": True})

    assert result["report_data_valid"] is False


def test_gateway_report_data_accepts_tls_cert_binding() -> None:
    result = _gateway_with_report_data(
        {"binds_address": False, "binds_tls_cert": True, "embeds_nonce": True}
    )

    assert result["report_data_valid"] is True


def test_gateway_report_data_still_requires_nonce() -> None:
    """A valid channel binding must not excuse a replayed quote."""
    result = _gateway_with_report_data(
        {"binds_address": True, "binds_tls_cert": True, "embeds_nonce": False}
    )

    assert result["report_data_valid"] is False


def _domain_item(**overrides: object) -> dict:
    item = {
        "domain": urlparse(BASE_URL).hostname or BASE_URL,
        "certificate_verified": True,
        "fingerprint_matches": True,
        "attestation_fingerprint_matches": True,
        "dns_caa_verified": True,
    }
    item.update(overrides)
    return item


def test_domain_certificate_valid_when_all_checks_pass() -> None:
    assert _validate_domain_certificate(_domain_item()) is True


def test_domain_certificate_requires_attested_fingerprint() -> None:
    assert (
        _validate_domain_certificate(
            _domain_item(attestation_fingerprint_matches=False)
        )
        is False
    )


def test_domain_certificate_rejects_absent_attested_fingerprint() -> None:
    item = _domain_item()
    del item["attestation_fingerprint_matches"]

    assert _validate_domain_certificate(item) is False


def test_legacy_struct_order_actions_hash_is_rejected() -> None:
    """Only the canonical (compose-manager PR #36) actions serialization binds."""
    # Keys not in alphabetical order, so the two serializations differ.
    actions = [{"tag": "v1", "action": "compose_up"}]
    canonical = json.dumps(
        actions, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    legacy = json.dumps(actions, separators=(",", ":"), ensure_ascii=False)
    assert canonical != legacy, "test vector must distinguish the two orderings"

    canonical_hash = hashlib.sha256(canonical.encode()).hexdigest()
    legacy_hash = hashlib.sha256(legacy.encode()).hexdigest()

    assert _actions_report_data_hash(actions) == canonical_hash
    assert _actions_report_data_hash(actions) != legacy_hash
