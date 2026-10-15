# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for verifier.main standalone-usability helpers."""

import argparse
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from verifier.main import (
    _WEIGHTS_CHAIN,
    _emit_report,
    _persistence_enabled,
    cli,
    record_serving_composes,
)
from verifier.models import create_verification_policy

MODEL = "z-ai/glm-5.3-flash"


class TestCli:
    def test_exits_cleanly_on_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def boom() -> None:
            raise RuntimeError("Attestation report fetch failed: HTTP 503")

        monkeypatch.setattr("verifier.main.main", boom)
        with pytest.raises(SystemExit) as exc:
            cli()
        assert exc.value.code == 1


class TestPersistenceEnabled:
    def test_disabled_without_bucket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NEAR_BUCKET_NAME", raising=False)
        assert _persistence_enabled(no_persist=False) is False

    def test_enabled_with_bucket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "bucket")
        assert _persistence_enabled(no_persist=False) is True

    def test_no_persist_overrides_bucket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEAR_BUCKET_NAME", "bucket")
        assert _persistence_enabled(no_persist=True) is False


class TestPolicyReproducibilityFlag:
    _REPOS = {"cloud-api": "nearai/cloud-api"}

    def test_policy_default_requires_reproducible(self) -> None:
        policy = create_verification_policy(self._REPOS)
        assert policy.require_reproducible_build is True

    def test_policy_can_skip_reproducible(self) -> None:
        policy = create_verification_policy(
            self._REPOS, require_reproducible_build=False
        )
        assert policy.require_reproducible_build is False

    def test_required_images_are_the_map_keys(self) -> None:
        assert create_verification_policy(self._REPOS).required_images == ["cloud-api"]


class TestEmitReport:
    _SUMMARIES = [{"type": "Gateway", "tdx_verified": True}]

    def _args(self, **kw: Any) -> argparse.Namespace:
        base: dict[str, Any] = {"output": None, "json": False}
        base.update(kw)
        return argparse.Namespace(**base)

    def test_writes_output_file(self, tmp_path: object) -> None:
        out = tmp_path / "report.json"  # type: ignore[operator]
        _emit_report(self._SUMMARIES, self._args(output=str(out)))
        assert json.loads(out.read_text()) == self._SUMMARIES

    def test_json_to_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        _emit_report(self._SUMMARIES, self._args(json=True))
        out = capsys.readouterr().out
        assert json.loads(out) == self._SUMMARIES

    def test_no_json_keeps_stdout_clean(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Without --json the report goes to logs (stderr), not stdout.
        _emit_report(self._SUMMARIES, self._args(json=False))
        assert capsys.readouterr().out == ""


class TestRecordOtherSchemeInferenceKeys:
    """The per-run sweep that captures signing keys for schemes the main pass
    did not already cover (so one run records both ecdsa and ed25519)."""

    def test_sweeps_only_uncovered_algos_and_records(self) -> None:
        import asyncio
        from unittest.mock import AsyncMock, patch

        from verifier import main

        summaries = [{"signing_algo": "ecdsa"}]  # ecdsa already covered
        captured = {
            "signing_public_key": "40ef",
            "signing_address": "40ef",
            "signing_algo": "ed25519",
            "model_name": MODEL,
        }
        with (
            patch.object(
                main, "capture_inference_signing_key", AsyncMock(return_value=captured)
            ) as cap,
            patch.object(main, "_record_signing_key") as rec,
        ):
            asyncio.run(main.record_other_scheme_inference_keys(MODEL, summaries, {}))
        # ecdsa is covered, so only ed25519 is swept.
        assert [c.args[2] for c in cap.call_args_list] == ["ed25519"]
        rec.assert_called_once()
        assert rec.call_args.kwargs["signing_algo"] == "ed25519"

    def test_no_record_when_capture_returns_none(self) -> None:
        import asyncio
        from unittest.mock import AsyncMock, patch

        from verifier import main

        with (
            patch.object(
                main, "capture_inference_signing_key", AsyncMock(return_value=None)
            ),
            patch.object(main, "_record_signing_key") as rec,
        ):
            asyncio.run(
                main.record_other_scheme_inference_keys(
                    MODEL, [{"signing_algo": "ecdsa"}], {}
                )
            )
        rec.assert_not_called()

    def test_capture_exception_is_swallowed(self) -> None:
        import asyncio
        from unittest.mock import AsyncMock, patch

        from verifier import main

        with (
            patch.object(
                main,
                "capture_inference_signing_key",
                AsyncMock(side_effect=RuntimeError("boom")),
            ),
            patch.object(main, "_record_signing_key") as rec,
        ):
            asyncio.run(
                main.record_other_scheme_inference_keys(
                    MODEL, [{"signing_algo": "ecdsa"}], {}
                )
            )
        rec.assert_not_called()


_GW_COMPOSE = '{"docker_compose_file": "services: {}"}'
_GW_MRCONFIG = (
    "01" + __import__("hashlib").sha256(_GW_COMPOSE.encode()).hexdigest()
).ljust(96, "0")


class TestCaptureGatewaySigningKey:
    # Gateway signing identity lives in gateway_attestation; ed25519 address ==
    # public key.
    def _report(self, algo: str = "ed25519") -> dict:
        return {
            "gateway_attestation": {
                "signing_algo": algo,
                "signing_address": "cb6fc58f",
                "intel_quote": "deadbeef",
            }
        }

    def _run(
        self,
        report: dict,
        *,
        verified: bool,
        binds: dict,
        mrconfig: str = "",
    ) -> dict[str, str] | None:
        mrconfig = mrconfig or _GW_MRCONFIG
        import asyncio
        from unittest.mock import AsyncMock, patch

        from verifier import verification_steps as vs

        quote = {"verified": verified, "quote": {"body": {"mrconfig": mrconfig}}}
        with (
            patch.object(vs, "fetch_attestation_report", return_value=report),
            patch.object(vs, "verify_tdx_quote", AsyncMock(return_value=quote)),
            patch.object(vs, "check_os_measurements", return_value=True),
            patch.object(vs, "check_report_data", return_value=binds),
        ):
            return asyncio.run(
                vs.capture_gateway_signing_key("m", "nn", "ed25519", _GW_COMPOSE)
            )

    def test_ecdsa_request_returns_none_without_fetching(self) -> None:
        import asyncio
        from unittest.mock import patch

        from verifier import verification_steps as vs

        with patch.object(vs, "fetch_attestation_report") as fetch:
            out = asyncio.run(
                vs.capture_gateway_signing_key("m", "nn", "ecdsa", _GW_COMPOSE)
            )
        assert out is None
        fetch.assert_not_called()

    def test_returns_key_when_binding_valid(self) -> None:
        out = self._run(
            self._report(),
            verified=True,
            binds={
                "binds_address": False,
                "binds_tls_cert": True,
                "embeds_nonce": True,
            },
        )
        assert out is not None
        assert out["signing_public_key"] == "cb6fc58f"
        assert out["signing_algo"] == "ed25519"

    def test_none_on_algo_mismatch(self) -> None:
        import asyncio
        from unittest.mock import patch

        from verifier import verification_steps as vs

        with patch.object(
            vs, "fetch_attestation_report", return_value=self._report("ecdsa")
        ):
            out = asyncio.run(
                vs.capture_gateway_signing_key("m", "nn", "ed25519", _GW_COMPOSE)
            )
        assert out is None

    def test_none_on_unverified_quote(self) -> None:
        out = self._run(
            self._report(),
            verified=False,
            binds={
                "binds_address": False,
                "binds_tls_cert": True,
                "embeds_nonce": True,
            },
        )
        assert out is None

    def test_none_when_binding_fails(self) -> None:
        out = self._run(
            self._report(),
            verified=True,
            binds={
                "binds_address": False,
                "binds_tls_cert": False,
                "embeds_nonce": True,
            },
        )
        assert out is None

    def test_address_only_binding_is_not_enough(self) -> None:
        # A gateway quote must bind the TLS cert; binds_address alone lets a
        # gateway proxy a genuine backend's quote (same bar as the main pass).
        out = self._run(
            self._report(),
            verified=True,
            binds={
                "binds_address": True,
                "binds_tls_cert": False,
                "embeds_nonce": True,
            },
        )
        assert out is None

    def test_none_when_cvm_runs_another_compose(self) -> None:
        out = self._run(
            self._report(),
            verified=True,
            binds={"binds_tls_cert": True, "embeds_nonce": True},
            mrconfig="01" + "ee" * 47,
        )
        assert out is None


class TestRecordOtherSchemeGatewayKey:
    def test_sweeps_uncovered_scheme_and_records(self) -> None:
        import asyncio
        from unittest.mock import AsyncMock, patch

        from verifier import main

        # Primary gateway scheme (ecdsa) lives in gateway_attestation.
        report = {"gateway_attestation": {"signing_algo": "ecdsa"}}
        captured = {
            "signing_public_key": "cb6fc58f",
            "signing_address": "cb6fc58f",
            "signing_algo": "ed25519",
        }
        with (
            patch.object(
                main, "capture_gateway_signing_key", AsyncMock(return_value=captured)
            ) as cap,
            patch.object(main, "_record_signing_key") as rec,
        ):
            asyncio.run(main.record_other_scheme_gateway_key("model", report))
        assert [c.args[2] for c in cap.call_args_list] == ["ed25519"]
        rec.assert_called_once()
        assert rec.call_args.kwargs["signing_algo"] == "ed25519"
        assert rec.call_args.kwargs["component"] == "Gateway"

    def test_no_record_when_capture_returns_none(self) -> None:
        import asyncio
        from unittest.mock import AsyncMock, patch

        from verifier import main

        with (
            patch.object(
                main, "capture_gateway_signing_key", AsyncMock(return_value=None)
            ),
            patch.object(main, "_record_signing_key") as rec,
        ):
            asyncio.run(
                main.record_other_scheme_gateway_key("model", {"signing_algo": "ecdsa"})
            )
        rec.assert_not_called()


class TestPinDriftRemediation:
    """The proxy pin's edit instruction names the model id, not the image."""

    HAVE = "e" * 40
    NEED = "2" * 40

    def _lines(self, registry: str, capsys: Any) -> str:
        # The block is printed to stdout (it is human-facing, not a log line).
        from verifier.main import _report_pin_drift

        msg = (
            f"Commit SHA mismatch for '{registry}': "
            f"expected: {self.HAVE} got: {self.NEED}"
        )
        _report_pin_drift(
            [{"image_verification": {"images": {"x": {"messages": [msg]}}}}]
        )
        return str(capsys.readouterr().err)

    def test_proxy_drift_names_the_model_id_as_the_key(self, capsys: Any) -> None:
        from verifier.config import MODEL_NAME

        text = self._lines("nearaidev/vllm-proxy-rs", capsys)
        assert "_PROXY_EXPECTED_COMMITS" in text
        # The edit must set the MODEL id, not the image registry.
        assert f'set "{MODEL_NAME}" to "{self.NEED}"' in text
        assert f'set "nearaidev/vllm-proxy-rs" to "{self.NEED}"' not in text

    def test_gateway_drift_still_names_the_registry(self, capsys: Any) -> None:
        text = self._lines("nearaidev/cloud-api", capsys)
        assert "_GATEWAY_EXPECTED_COMMITS" in text
        assert f'set "nearaidev/cloud-api" to "{self.NEED}"' in text

    def test_shared_inference_drift_names_the_registry(self, capsys: Any) -> None:
        text = self._lines("nearaidev/compose-manager", capsys)
        assert "_INFERENCE_EXPECTED_COMMITS" in text
        assert f'set "nearaidev/compose-manager" to "{self.NEED}"' in text


class TestRecordServingComposes:
    def _compose(self, sha: str, approved: bool) -> dict[str, object]:
        return {
            "file": "f.yaml",
            "commit": "c",
            "file_sha256": sha,
            "approved": approved,
        }

    def _run(self, **summary: object) -> tuple[MagicMock, MagicMock]:
        base: dict[str, object] = {
            **dict.fromkeys(_WEIGHTS_CHAIN, True),
            # The proxy failed: the weights markers do not depend on it.
            "near_images_verified": False,
            "model_name": "m/a",
            "compose_log": "h" * 64,
            "serving_composes": [
                self._compose("d" * 64, True),
                self._compose("e" * 64, True),
            ],
        }
        with (
            patch("verifier.main.save_serving_compose") as compose,
            patch("verifier.main.save_serving_log") as log,
        ):
            record_serving_composes([{**base, **summary}])
        return compose, log

    def test_records_approved_files_and_the_log(self) -> None:
        compose, log = self._run()
        assert [c.args[:2] for c in compose.call_args_list] == [
            ("m/a", "d" * 64),
            ("m/a", "e" * 64),
        ]
        assert log.call_args.args[:2] == ("m/a", "h" * 64)

    def test_skips_the_log_when_a_file_is_unapproved(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The relay blesses history up to the head marker, so the marker must
        # not be written while a file it names was never approved.
        compose, log = self._run(
            serving_composes=[
                self._compose("d" * 64, True),
                self._compose("e" * 64, False),
            ]
        )
        assert [c.args[:2] for c in compose.call_args_list] == [("m/a", "d" * 64)]
        log.assert_not_called()
        assert "f.yaml" in caplog.text

    def test_skips_unapproved_weights(self) -> None:
        compose, log = self._run(model_weights_approved=False)
        compose.assert_not_called()
        log.assert_not_called()

    def test_skips_without_compose_log(self) -> None:
        compose, log = self._run(compose_log="")
        compose.assert_not_called()
        log.assert_not_called()

    @pytest.mark.parametrize("check", _WEIGHTS_CHAIN)
    def test_skips_when_any_weights_check_fails(self, check: str) -> None:
        compose, log = self._run(**{check: False})
        compose.assert_not_called()
        log.assert_not_called()
