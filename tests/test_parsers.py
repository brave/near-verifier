# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Direct tests for the parsers that read untrusted provenance and GPU tokens."""

import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from verifier.verifications import gpu, provenance

REPO = "https://github.com/nearai/cloud-api"
SHA = "a" * 40
BUILDER = (
    "https://github.com/nearai/cloud-api/.github/workflows/build.yml@refs/heads/main"
)


def test_slsa_v1_reads_repo_commit_and_builder() -> None:
    info = provenance._parse_provenance(
        {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "resolvedDependencies": [
                    {"uri": "pkg:docker/base"},
                    {
                        "uri": f"git+{REPO}@refs/heads/main",
                        "digest": {"gitCommit": SHA},
                    },
                ],
            },
            "runDetails": {"builder": {"id": BUILDER}},
        }
    )
    assert info is not None
    assert (info.source_repo, info.commit_sha, info.builder_id) == (REPO, SHA, BUILDER)


def test_slsa_v02_reads_repo_commit_and_builder() -> None:
    info = provenance._parse_provenance(
        {
            "builder": {"id": BUILDER},
            "materials": [{"uri": f"git+{REPO}@{SHA}"}],
        }
    )
    assert info is not None
    assert (info.source_repo, info.commit_sha, info.builder_id) == (REPO, SHA, BUILDER)


def test_unknown_predicate_and_missing_source() -> None:
    assert provenance._parse_provenance({"other": 1}) is None
    info = provenance._parse_provenance({"buildDefinition": {}})
    assert info is not None
    assert info.commit_sha == "unknown"


@pytest.mark.parametrize("sha", ["unknown", "A" * 40, "a" * 39, "g" * 40])
def test_malformed_commit_fails_policy(sha: str) -> None:
    ok, _ = provenance._validate_commit_sha(sha)
    assert ok is False
    assert provenance._validate_commit_sha(SHA)[0] is True


def _token(alg: str, key: object, payload: dict[str, object]) -> str:
    return jwt.encode(payload, key, algorithm=alg)


def test_gpu_jwt_rejects_a_disallowed_algorithm() -> None:
    token = _token("HS256", "s" * 32, {"eat_nonce": "ab"})
    with pytest.raises(jwt.exceptions.InvalidAlgorithmError):
        gpu._verify_and_decode_gpu_jwt(token)


def _decode_with_key(token: str, key: object) -> dict[str, object]:
    client = MagicMock()
    client.get_signing_key_from_jwt.return_value = MagicMock(key=key)
    with patch.object(gpu, "_jwks_client", return_value=client):
        return gpu._verify_and_decode_gpu_jwt(token)


def test_gpu_jwt_checks_the_signature_against_the_jwks_key() -> None:
    signer = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    claims = {"eat_nonce": "ab", "exp": int(time.time()) + 60}
    token = _token("ES256", signer, claims)
    assert _decode_with_key(token, signer.public_key()) == claims
    with pytest.raises(jwt.exceptions.InvalidSignatureError):
        _decode_with_key(token, other.public_key())


def test_gpu_jwt_without_expiry_is_rejected() -> None:
    signer = ec.generate_private_key(ec.SECP256R1())
    token = _token("ES256", signer, {"eat_nonce": "ab"})
    with pytest.raises(jwt.exceptions.MissingRequiredClaimError):
        _decode_with_key(token, signer.public_key())
