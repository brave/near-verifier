# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Fail-closed tests:

- cosign identity regexps are anchored (no prefix/suffix smuggling),
- GPU validation fails closed when no GPU was actually attested (vacuous pass),
- GPU freshness is taken from the NVIDIA-signed JWT nonce, not the payload,
- CAA authorization is an exact issuer match, not a substring.
"""

import re

from verifier.config import CERT_IDENTITY_REGEXP
from verifier.validation import ValidationResult
from verifier.verifications.gpu import _signed_jwt_nonce_matches


class TestIdentityRegexpAnchoring:
    def test_all_patterns_anchored(self) -> None:
        for image, pattern in CERT_IDENTITY_REGEXP.items():
            assert pattern.startswith("^"), f"{image} pattern not start-anchored"
            assert pattern.endswith("$"), f"{image} pattern not end-anchored"

    def test_legit_builder_identity_matches(self) -> None:
        legit = (
            "https://github.com/nearai/cloud-api/"
            ".github/workflows/build.yml@refs/heads/main"
        )
        assert re.search(CERT_IDENTITY_REGEXP["nearaidev/cloud-api"], legit)

    def test_prefix_smuggled_identity_rejected(self) -> None:
        # Without the leading ^, an unanchored RE2 match would accept a SAN that
        # merely *contains* the expected workflow path.
        smuggled = (
            "https://evil.example/?u=https://github.com/nearai/cloud-api/"
            ".github/workflows/build.yml@refs/heads/main"
        )
        assert re.search(CERT_IDENTITY_REGEXP["nearaidev/cloud-api"], smuggled) is None


class TestGpuVacuousPass:
    def _base(self) -> ValidationResult:
        # inference_components_seen=1 so only the GPU guard is under test here.
        return ValidationResult(
            gateway=True,
            domain_tls=True,
            inference_all=True,
            inference_components_seen=1,
        )

    def test_no_gpu_component_fails_closed(self) -> None:
        # gpu_all defaults True, but zero GPU components were evaluated -> invalid.
        result = self._base()
        assert result.gpu_components_seen == 0
        assert result.is_valid() is False
        assert "gpu_all" in result.failed_checks()

    def test_one_verified_gpu_component_passes(self) -> None:
        result = self._base()
        result.gpu_components_seen = 1
        assert result.is_valid() is True

    def test_failed_gpu_component_still_fails(self) -> None:
        result = self._base()
        result.gpu_components_seen = 1
        result.gpu_all = False
        assert result.is_valid() is False


class TestInferenceVacuousPass:
    """A report with no inference component must not pass on the default True."""

    def _base(self) -> ValidationResult:
        return ValidationResult(
            gateway=True, domain_tls=True, gpu_all=True, gpu_components_seen=1
        )

    def test_no_inference_component_fails_closed(self) -> None:
        result = self._base()
        assert result.inference_components_seen == 0
        assert result.is_valid() is False
        assert "inference_all" in result.failed_checks()

    def test_one_verified_inference_component_passes(self) -> None:
        result = self._base()
        result.inference_components_seen = 1
        assert result.is_valid() is True

    def test_failed_inference_component_still_fails(self) -> None:
        result = self._base()
        result.inference_components_seen = 1
        result.inference_all = False
        assert result.is_valid() is False


class TestSignedJwtNonce:
    NONCE = "ab" * 32  # 64 hex chars

    def test_matching_eat_nonce(self) -> None:
        assert _signed_jwt_nonce_matches({"eat_nonce": self.NONCE}, self.NONCE) is True

    def test_mismatched_nonce_detected(self) -> None:
        assert _signed_jwt_nonce_matches({"eat_nonce": "cd" * 32}, self.NONCE) is False

    def test_nonce_claim_as_list(self) -> None:
        assert _signed_jwt_nonce_matches({"nonce": [self.NONCE]}, self.NONCE) is True

    def test_no_recognizable_claim_returns_none(self) -> None:
        # None, which the caller treats as a failed nonce check.
        assert _signed_jwt_nonce_matches({"sub": "x"}, self.NONCE) is None

    def test_unrecognized_encoding_returns_none(self) -> None:
        # Unrecognized encodings also return None, so they fail closed too.
        result = _signed_jwt_nonce_matches({"eat_nonce": "Zm9vYmFy=="}, self.NONCE)
        assert result is None

    def test_0x_prefixes_normalized(self) -> None:
        result = _signed_jwt_nonce_matches(
            {"eat_nonce": "0x" + self.NONCE}, "0x" + self.NONCE
        )
        assert result is True


class TestCaaExactMatch:
    """verify_dns_caa must require an exact issuer-domain match."""

    def _run(self, *record_values: str) -> bool:
        import asyncio
        from unittest.mock import MagicMock, patch

        response = MagicMock()
        response.ok = True
        response.json.return_value = {
            "Answer": [{"type": 257, "data": v} for v in record_values]
        }
        session = MagicMock()
        session.get.return_value = response
        from verifier.verifications import tls

        with patch.object(tls, "get_http_session", return_value=session):
            return asyncio.run(tls.verify_dns_caa("cloud-api.near.ai"))

    def test_exact_issuer_authorizes(self) -> None:
        assert self._run('0 issue "letsencrypt.org"') is True

    def test_issuer_with_parameters_authorizes(self) -> None:
        assert self._run('0 issue "letsencrypt.org; validationmethods=dns-01"') is True

    def test_subdomain_smuggle_rejected(self) -> None:
        assert self._run('0 issue "letsencrypt.org.attacker.example"') is False

    def test_prefix_smuggle_rejected(self) -> None:
        assert self._run('0 issue "notletsencrypt.org"') is False

    def test_iodef_and_forbidden_wildcard_are_allowed(self) -> None:
        assert (
            self._run(
                '0 issue "letsencrypt.org"',
                '0 iodef "mailto:security@example.com"',
                '0 issuewild ";"',
            )
            is True
        )

    def test_second_ca_or_no_issue_record_rejected(self) -> None:
        assert self._run('0 issue "letsencrypt.org"', '0 issue "other.ca"') is False
        assert self._run('0 issuewild "letsencrypt.org"') is False
        assert self._run('0 iodef "mailto:x@example.com"') is False


def test_builder_wildcard_does_not_match_sibling_repo() -> None:
    from verifier.verifications.provenance import _matches_pattern

    pattern = "https://github.com/nearai/cloud-api/*"
    assert _matches_pattern(
        "https://github.com/nearai/cloud-api/.github/workflows/build.yml", pattern
    )
    assert not _matches_pattern(
        "https://github.com/nearai/cloud-api-evil/.github/workflows/build.yml", pattern
    )
