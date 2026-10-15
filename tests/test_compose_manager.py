# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for the inference-CVM compose-manager verification chain."""

import asyncio
import json
from hashlib import sha256
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from verifier.models import VerificationPolicy
from verifier.verifications import compose_manager as cm

_POLICY = VerificationPolicy(
    allowed_repos=["https://github.com/nearai/compose-manager"],
    allowed_builders=["https://github.com/nearai/compose-manager/*"],
    required_images=["nearaidev/compose-manager", "nearaidev/vllm-proxy-rs"],
    require_reproducible_build=True,
    skip_reproducibility_images=set(),
)

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures_inference_attestation.json").read_text()
)
NONCE = FIXTURE["request_nonce"]
REPORT_DATA = FIXTURE["compose_manager_attestation"]["report_data"]
# Inference-proxy report_data layout: signing_address (20B, zero-padded to 32B)
# then the request nonce (32B).
PROXY_REPORT_DATA = FIXTURE["signing_address"].removeprefix("0x") + "00" * 12 + NONCE
# Shared TDX measurements proving both quotes come from one CVM.
MEAS: dict[str, Any] = {
    "mrtd": "ab" * 24,
    "rtmrs": ["00" * 24, "11" * 24, "22" * 24, "33" * 24],
}

MEAS_PIN = frozenset({(MEAS["mrtd"], *MEAS["rtmrs"][:3])})


@pytest.fixture(autouse=True)
def _pin_meas() -> Any:
    """Pin the test measurements so the OS-measurement gate passes."""
    with patch("verifier.verifications.tdx.EXPECTED_OS_MEASUREMENTS", MEAS_PIN):
        yield


def _intel_result(
    reportdata: str,
    mrconfig: str = "",
    verified: bool = True,
    mrtd: str = MEAS["mrtd"],
    rtmrs: list[str] | None = None,
) -> Any:
    return {
        "quote": {
            "body": {
                "reportdata": reportdata,
                "mrconfig": mrconfig,
                "mrtd": mrtd,
                "rtmrs": rtmrs if rtmrs is not None else list(MEAS["rtmrs"]),
            }
        },
        "verified": verified,
    }


class TestPureHelpers:
    def test_model_names_match(self) -> None:
        assert cm.model_names_match("z-ai/glm-5.3-flash", "z-ai/glm-5.3-flash")
        # Case and surrounding whitespace are not a substitution.
        assert cm.model_names_match("Z-AI/GLM-5.3-Flash", "z-ai/glm-5.3-flash")
        assert cm.model_names_match(" z-ai/glm-5.3-flash ", "z-ai/glm-5.3-flash")

    def test_model_names_mismatch(self) -> None:
        assert not cm.model_names_match("z-ai/glm-5.3-flash", "zai-org/GLM-5.1-FP8")
        # A near-miss on the same family is still a mismatch.
        assert not cm.model_names_match("z-ai/glm-5.3", "z-ai/glm-5.3-flash")
        # An attestation that does not say what it is for can never match.
        assert not cm.model_names_match("", "z-ai/glm-5.3-flash")

    def test_check_compose_hash_matches(self) -> None:
        assert cm._check_compose_hash(FIXTURE) is True

    def test_check_compose_hash_rejects_tampered_app_compose(self) -> None:
        tampered = json.loads(json.dumps(FIXTURE))
        tampered["info"]["tcb_info"]["app_compose"] += " "
        assert cm._check_compose_hash(tampered) is False

    def test_boot_docker_compose_extracts_yaml(self) -> None:
        boot = cm._boot_docker_compose(FIXTURE)
        assert "nearaidev/compose-manager@sha256:" in boot

    def test_all_images_fully_verified_all_reproducible(self) -> None:
        iv: Any = {
            "images": {
                "nearaidev/compose-manager@sha256:a": {
                    "provenance_verified": True,
                    "build_reproducible": True,
                }
            }
        }
        assert cm.all_images_fully_verified(iv, _POLICY) is True

    def test_all_images_fully_verified_empty_fails(self) -> None:
        iv: Any = {"images": {}}
        assert cm.all_images_fully_verified(iv, _POLICY) is False

    def test_all_images_fully_verified_unreproducible_fails(self) -> None:
        iv: Any = {
            "images": {
                "nearaidev/compose-manager@sha256:a": {
                    "provenance_verified": True,
                    "build_reproducible": False,
                }
            }
        }
        assert cm.all_images_fully_verified(iv, _POLICY) is False

    def test_all_images_fully_verified_unverified_provenance_fails(self) -> None:
        iv: Any = {
            "images": {
                "nearaidev/compose-manager@sha256:a": {
                    "provenance_verified": False,
                    "build_reproducible": True,
                }
            }
        }
        assert cm.all_images_fully_verified(iv, _POLICY) is False

    def test_compose_log_chain_covers_only_compose_actions(self) -> None:
        up = {"action": "compose_up", "file": "a.yaml", "services": ["s"]}
        chain = cm.compose_log_chain([up, {"action": "docker_clean"}, up])
        assert len(chain) == 2 and chain[0] != chain[1]
        assert cm.compose_log_chain([up])[0] == chain[0]
        assert cm.compose_log_chain([{"action": "docker_clean"}]) == []

    def test_running_compose_manager_image_returns_latest_started(self) -> None:
        # compose-manager self-updates; the running image is the most recent
        # compose_manager_started entry, not an earlier one or the boot image.
        older = "nearaidev/compose-manager@sha256:" + "a" * 64
        newer = "nearaidev/compose-manager@sha256:" + "b" * 64
        actions = [
            {"action": "compose_manager_started", "image": older},
            {"action": "compose_up", "file": "small-models.yaml"},
            {"action": "compose_manager_started", "image": newer},
            {"action": "docker_restart"},
        ]
        assert cm._running_compose_manager_image(actions) == newer

    def test_running_compose_manager_image_empty_when_absent(self) -> None:
        # No started entry -> "" so the caller falls back to boot.
        assert cm._running_compose_manager_image([{"action": "compose_up"}]) == ""


_BOOT_CM = (
    "services:\n  compose-manager:\n    image: ${COMPOSE_MANAGER_IMAGE:-"
    "nearaidev/compose-manager@sha256:" + "a" * 64 + "}\n"
)


_BOOT_REF = "nearaidev/compose-manager@sha256:" + "a" * 64


def _boot_result(
    commit: str = "b" * 40, provenance_ok: bool = True, reproducible: bool = True
) -> dict[str, Any]:
    return {
        "image": _BOOT_REF,
        "provenance_found": True,
        "provenance_verified": provenance_ok,
        "build_reproducible": reproducible,
        "provenance": {"commit_sha": commit},
        "messages": [],
    }


def _boot(
    result: dict[str, Any] | None,
    reviewed: frozenset[str] = frozenset({"b" * 40}),
    envs: frozenset[str] = frozenset(),
    already: dict[str, Any] | None = None,
) -> tuple[bool, Any, Any]:
    full = MagicMock(return_value=result)
    with (
        patch.object(cm, "verify_image_full", full),
        patch.object(cm, "BOOT_COMPOSE_MANAGER_COMMITS", reviewed),
    ):
        ok, out = cm._verify_boot_compose_manager(
            _BOOT_CM, _POLICY, envs, already or {}
        )
    return ok, out, full


class TestBootComposeManager:
    def test_boot_fully_verified_at_reviewed_commit(self) -> None:
        ok, out, full = _boot(_boot_result())
        assert ok is True
        assert out["provenance"]["commit_sha"] == "b" * 40
        # The reviewed set replaces the running pin for the boot image.
        assert full.call_args.kwargs["allowed_commits"] == frozenset({"b" * 40})

    def test_boot_unreviewed_commit_fails(self) -> None:
        # The boot build vouches for the actions log, so its commit must be
        # one a human reviewed even when everything else verifies.
        ok, _, _ = _boot(_boot_result(), reviewed=frozenset({"c" * 40}))
        assert ok is False

    def test_boot_not_reproducible_fails(self) -> None:
        ok, _, _ = _boot(_boot_result(reproducible=False))
        assert ok is False

    def test_boot_provenance_failure_fails(self) -> None:
        ok, _, _ = _boot(_boot_result(provenance_ok=False))
        assert ok is False

    def test_boot_reuses_running_result_but_still_checks_commit(self) -> None:
        # Boot == running image: no second rebuild, but the running pin is
        # not automatically a reviewed boot commit.
        running = _boot_result(commit="d" * 40)
        ok, _, full = _boot(None, already={_BOOT_REF: running})
        full.assert_not_called()
        assert ok is False
        ok, _, _ = _boot(
            None, reviewed=frozenset({"d" * 40}), already={_BOOT_REF: running}
        )
        assert ok is True

    def test_boot_with_two_compose_managers_fails(self) -> None:
        second = (
            "  cm2:\n    image: nearaidev/compose-manager@sha256:" + "e" * 64 + "\n"
        )
        with patch.object(cm, "verify_image_full", MagicMock()) as full:
            ok, out = cm._verify_boot_compose_manager(
                _BOOT_CM + second, _POLICY, frozenset(), {}
            )
        assert (ok, out) == (False, None)
        full.assert_not_called()

    def test_boot_no_compose_manager_image_fails_closed(self) -> None:
        # No compose-manager image in the boot compose -> can't anchor -> fail.
        ok, out = cm._verify_boot_compose_manager(
            "services: {}", _POLICY, frozenset(), {}
        )
        assert (ok, out) == (False, None)

    def test_boot_image_from_operator_overridable_env_fails(self) -> None:
        # COMPOSE_MANAGER_IMAGE in allowed_envs means the operator picks the boot
        # image at deploy time; the digest default proves nothing then.
        ok, _, full = _boot(_boot_result(), envs=frozenset({"COMPOSE_MANAGER_IMAGE"}))
        assert ok is False
        full.assert_not_called()

    def test_boot_compose_manager_exempt_from_pre_launch_script(self) -> None:
        # NEAR's pre_launch_script restores the launcher's last choice of
        # compose-manager; the launcher is verified separately.
        ok, _, _ = _boot(_boot_result(), envs=frozenset({"*"}))
        assert ok is True

    def test_other_boot_image_not_exempt_from_pre_launch_script(self) -> None:
        launcher = "nearaidev/vllm-proxy-rs"  # any other required image
        boot = _BOOT_CM + f"  x:\n    image: ${{X:-{launcher}@sha256:{'f' * 64}}}\n"
        with (
            patch.object(cm, "verify_image_full", MagicMock()) as full,
            patch.object(cm, "BOOT_COMPOSE_MANAGER_COMMITS", frozenset({"b" * 40})),
        ):
            ok, _ = cm._verify_boot_compose_manager(boot, _POLICY, frozenset({"*"}), {})
        assert ok is False
        full.assert_not_called()

    def test_measurements_include_rtmr3(self) -> None:
        a = _intel_result("", mrconfig="cfg", mrtd="td", rtmrs=["0", "1", "2", "A"])
        b = _intel_result("", mrconfig="cfg", mrtd="td", rtmrs=["0", "1", "2", "B"])
        # Differ only in rtmr3: two replicas of one app.
        assert cm._measurements(a) != cm._measurements(b)

    def test_measurements_present_requires_mrtd_and_mrconfig(self) -> None:
        assert cm._measurements_present(("td", "cfg", "0", "1", "2")) is True
        assert cm._measurements_present(("", "", "0", "1", "2")) is False
        assert cm._measurements_present(("td", "", "0")) is False


class TestVerifyComposeManagerQuote:
    def test_binds_actions_hash_and_nonce(self) -> None:
        with patch.object(
            cm, "verify_tdx_quote", AsyncMock(return_value=_intel_result(REPORT_DATA))
        ):
            tdx, ah_bound, nonce_bound, intel = asyncio.run(
                cm._verify_compose_manager_quote(
                    FIXTURE["compose_manager_attestation"], NONCE
                )
            )
        assert (tdx, ah_bound, nonce_bound) == (True, True, True)
        assert intel is not None

    def test_wrong_nonce_fails_nonce_binding(self) -> None:
        with patch.object(
            cm, "verify_tdx_quote", AsyncMock(return_value=_intel_result(REPORT_DATA))
        ):
            _, ah_bound, nonce_bound, _ = asyncio.run(
                cm._verify_compose_manager_quote(
                    FIXTURE["compose_manager_attestation"], "ff" * 32
                )
            )
        assert ah_bound is True
        assert nonce_bound is False

    def test_tampered_actions_fails_binding(self) -> None:
        # Forging the actions log breaks the binding: the recomputed hash of the
        # tampered actions no longer equals the hardware-signed report_data.
        cma = json.loads(json.dumps(FIXTURE["compose_manager_attestation"]))
        cma["actions"].append(
            {"action": "compose_up", "file": "attacker.yaml", "commit": "deadbeef"}
        )
        with patch.object(
            cm, "verify_tdx_quote", AsyncMock(return_value=_intel_result(REPORT_DATA))
        ):
            _, ah_bound, _, _ = asyncio.run(
                cm._verify_compose_manager_quote(cma, NONCE)
            )
        assert ah_bound is False

    def test_tampered_actions_hash_field_alone_does_not_unbind(self) -> None:
        # The binding is the recomputed hash of the actions, not the
        # attacker-supplied actions_hash field.
        cma = json.loads(json.dumps(FIXTURE["compose_manager_attestation"]))
        cma["actions_hash"] = "ab" * 32
        with patch.object(
            cm, "verify_tdx_quote", AsyncMock(return_value=_intel_result(REPORT_DATA))
        ):
            _, ah_bound, _, _ = asyncio.run(
                cm._verify_compose_manager_quote(cma, NONCE)
            )
        assert ah_bound is True

    def test_actions_report_data_hashes_matches_pr_vector(self) -> None:
        # Locks our canonicalization to compose-manager PR #36's documented
        # Python equivalent / test vector.
        actions = [
            {
                "action": "compose_up",
                "tag": "v1",
                "timestamp": "2026-01-01T00:00:00+00:00",
            }
        ]
        canonical = cm._actions_report_data_hash(actions)
        assert (
            canonical
            == "381eb48dc299dafbbcd49c1a009998240f641865f35e435d2f07385c6e6b2a23"
        )

    def test_missing_quote_returns_all_false(self) -> None:
        result = asyncio.run(cm._verify_compose_manager_quote({}, NONCE))
        assert result == (False, False, False, None)


class TestFetchAndVerifyServingYaml:
    def _session(self, content: bytes, ok: bool = True) -> MagicMock:
        resp = MagicMock(ok=ok, content=content, text=content.decode())
        session = MagicMock()
        session.get.return_value = resp
        return session

    def test_verifies_matching_sha256_returns_text(self) -> None:
        yaml = b"services:\n  m:\n    image: nearaidev/x@sha256:" + b"a" * 64 + b"\n"
        digest = sha256(yaml).hexdigest()
        with patch.object(cm, "get_http_session", return_value=self._session(yaml)):
            ok, text = cm.fetch_and_verify_serving_yaml("commit", "f.yaml", digest)
        assert ok is True
        assert text == yaml.decode()

    def test_rejects_sha256_mismatch(self) -> None:
        yaml = b"services: {}\n"
        with patch.object(cm, "get_http_session", return_value=self._session(yaml)):
            ok, text = cm.fetch_and_verify_serving_yaml("c", "f.yaml", "00" * 32)
        assert ok is False
        assert text == ""

    def test_handles_http_failure(self) -> None:
        with patch.object(
            cm, "get_http_session", return_value=self._session(b"", ok=False)
        ):
            ok, text = cm.fetch_and_verify_serving_yaml("c", "f.yaml", "00" * 32)
        assert ok is False
        assert text == ""


class TestModelWeights:
    MODEL = "z-ai/glm-5.3-flash"
    SNAP = "/root/.cache/huggingface/hub/models--{}/snapshots/{}"
    QUANT = SNAP.format(
        "graphistry--GLM-5.3-Flash-W4AFP8", "99f1fa70408c52b007d4fd69e02e5a522422e755"
    )

    def _compose(self, *commands: Any) -> str:
        return json.dumps(
            {"services": {f"s{i}": {"command": c} for i, c in enumerate(commands)}}
        )

    def test_approved_snapshot_passes(self) -> None:
        compose = self._compose(
            f"python -m sglang.launch_server --model-path {self.QUANT} --tp 4",
            ["--model-path", self.QUANT],
        )
        assert (
            cm.serving_weights(compose)
            == [
                "graphistry/GLM-5.3-Flash-W4AFP8@99f1fa70408c52b007d4fd69e02e5a522422e755"
            ]
            * 2
        )
        assert cm.model_weights_approved(compose, self.MODEL) is True

    def test_unapproved_revision_fails(self) -> None:
        path = self.SNAP.format("graphistry--GLM-5.3-Flash-W4AFP8", "0" * 40)
        assert (
            cm.model_weights_approved(self._compose(f"--model-path {path}"), self.MODEL)
            is False
        )

    def test_one_unapproved_service_fails(self) -> None:
        other = self.SNAP.format("PhalaCloud--GLM-5.2-W4AFP8", "1" * 40)
        compose = self._compose(f"--model-path {self.QUANT}", f"--model-path {other}")
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def test_unpinned_repo_id_fails(self) -> None:
        compose = self._compose("--model-path graphistry/GLM-5.3-Flash-W4AFP8")
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def test_no_model_path_fails(self) -> None:
        assert cm.model_weights_approved(self._compose("serve x"), self.MODEL) is False
        assert cm.model_weights_approved("services: {}", self.MODEL) is False

    def test_comment_cannot_supply_weights(self) -> None:
        compose = (
            f"# --model-path {self.QUANT}\nservices:\n  s:\n    command: serve x\n"
        )
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def test_unknown_model_fails(self) -> None:
        compose = self._compose(f"--model-path {self.QUANT}")
        assert cm.model_weights_approved(compose, "z-ai/other") is False

    @pytest.mark.parametrize(
        "path",
        [
            QUANT + "/../../../models--evil--m/snapshots/" + "a" * 40,
            "${MODEL_PATH:-" + QUANT + "}",
            "/data" + QUANT,
            QUANT.replace("/root/.cache/huggingface/hub", "/data/attacker"),
        ],
        ids=["traversal", "env-default", "prefixed", "other-dir"],
    )
    def test_approved_snapshot_inside_other_path_fails(self, path: str) -> None:
        compose = self._compose(["sglang", "serve", "--model-path", path])
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def test_model_alias_is_checked(self) -> None:
        compose = self._compose(
            f"sglang serve --model-path {self.QUANT}", "sglang serve --model /evil"
        )
        assert cm.serving_weights(compose)[1] == "/evil"
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def test_server_without_model_path_fails(self) -> None:
        compose = json.dumps(
            {
                "services": {
                    "a": {"command": f"sglang serve --model-path {self.QUANT}"},
                    "b": {"command": "--served-model-name z-ai/glm-5.3-flash"},
                    "c": {"image": "vllm/vllm-openai@sha256:x", "command": "org/m"},
                }
            }
        )
        assert cm.serving_weights(compose)[1:] == [
            "b: no model path",
            "c: no model path",
        ]
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def test_argv_forms_are_read(self) -> None:
        compose = self._compose(
            ["sh", "-c", f"exec sglang serve --model-path {self.QUANT}"],
            f"sglang serve --model-path='{self.QUANT}'",
            f'sglang serve --model "{self.QUANT}"',
        )
        assert len(set(cm.serving_weights(compose))) == 1
        assert cm.model_weights_approved(compose, self.MODEL) is True

    def test_chat_template_and_tokenizer_are_pinned(self) -> None:
        template = self.SNAP.format(
            "zai-org--GLM-5.3-Flash", "3f1971b7b5f7a528c9c4ef6212c8785298a8c24a"
        )
        ok = (
            f"sglang serve --model-path {self.QUANT}"
            f" --chat-template {template}/chat_template.jinja"
        )
        assert cm.model_weights_approved(self._compose(ok), self.MODEL) is True
        for flag, path in [
            ("--chat-template", "/templates/evil.jinja"),
            ("--chat-template", self.SNAP.format("zai-org--GLM-5.3-Flash", "0" * 40)),
            ("--tokenizer-path", template + "/../../../models--evil--t"),
            ("--speculative-draft-model-path", "evil/draft"),
        ]:
            compose = self._compose(
                f"sglang serve --model-path {self.QUANT} {flag} {path}"
            )
            assert cm.model_weights_approved(compose, self.MODEL) is False, flag

    @pytest.mark.parametrize(
        "command",
        [
            "vllm serve /evil --model {q}",
            "sglang serve --model-path {q} --model-pa /evil",
            "sglang serve --model-path {q} --chat_template /evil.jinja",
            "sglang serve --model_path /evil",
        ],
        ids=["positional", "abbreviation", "underscore-artifact", "underscore-model"],
    )
    def test_argparse_spellings_are_checked(self, command: str) -> None:
        compose = self._compose(command.format(q=self.QUANT))
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def _file(self, **extra: Any) -> str:
        server = {"command": f"sglang serve --model-path {self.QUANT}"}
        return json.dumps(
            {"services": {"m": server, "x": {"image": "alpine", **extra}}}
        )

    @pytest.mark.parametrize(
        "extra",
        [
            {"runtime": "nvidia"},
            {"privileged": True},
            {"environment": ["NVIDIA_VISIBLE_DEVICES=all"]},
            {
                "deploy": {
                    "resources": {
                        "reservations": {"devices": [{"capabilities": ["gpu"]}]}
                    }
                }
            },
            {"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]},
            {"devices": ["/var/run/docker.sock:/var/run/docker.sock"]},
            {"devices": ["/var/run/docker.sock:/var/run/docker.sock:rwm"]},
        ],
        ids=[
            "runtime",
            "privileged",
            "visible-devices",
            "reservation",
            "docker-sock",
            "device-sock",
            "device-sock-modes",
        ],
    )
    def test_file_with_gpu_or_socket_sidecar_is_not_approved(
        self, extra: dict[str, Any]
    ) -> None:
        assert cm.compose_file_approved(self._file(), self.MODEL) is True
        assert cm.compose_file_approved(self._file(**extra), self.MODEL) is False

    def test_gpu_tools_and_disabled_gpus_are_approved(self) -> None:
        dcgm = {
            "image": "nvcr.io/nvidia/k8s/dcgm-exporter@sha256:x",
            "runtime": "nvidia",
        }
        compose = json.dumps(
            {
                "services": {
                    "d": dcgm,
                    "v": {"environment": {"NVIDIA_VISIBLE_DEVICES": "void"}},
                }
            }
        )
        assert cm.compose_file_approved(compose, self.MODEL) is True

    def test_listed_maintenance_file_is_approved(self) -> None:
        compose = self._file(volumes=["/var/run/docker.sock:/var/run/docker.sock"])
        digest = sha256(compose.encode()).hexdigest()
        with patch.object(cm, "APPROVED_MAINTENANCE_COMPOSES", frozenset({digest})):
            assert cm.compose_file_approved(compose, self.MODEL) is True

    @pytest.mark.parametrize(
        "extra",
        [
            "--lora-paths a=/evil",
            "--lora-modules a=/evil",
            "--speculative-config {}",
            "--load-format dummy",
            "--model-path ${EVIL:-x}",
            "--chat-template $TEMPLATE",
        ],
        ids=["lora-paths", "lora-modules", "spec-config", "dummy", "brace", "bare"],
    )
    def test_weight_changing_flags_fail(self, extra: str) -> None:
        compose = self._compose(f"sglang serve --model-path {self.QUANT} {extra}")
        assert cm.model_weights_approved(compose, self.MODEL) is False

    def test_escaped_dollar_is_not_interpolation(self) -> None:
        compose = self._compose(
            ["sh", "-c", f"echo $$HOME; exec sglang serve --model-path {self.QUANT}"]
        )
        assert cm.model_weights_approved(compose, self.MODEL) is True

    @pytest.mark.parametrize(
        "volume",
        [
            "/var/run/dstack.sock:/var/run/dstack.sock",
            "/var/run/tappd.sock:/var/run/tappd.sock",
            "/var/run:/host-run",
            "/run/:/r",
            "${SOCK}:/s",
            {"type": "bind", "source": "/var/run", "target": "/r"},
        ],
        ids=["dstack", "tappd", "var-run", "run", "interpolated", "long-syntax"],
    )
    def test_sidecar_socket_mount_is_not_approved(self, volume: Any) -> None:
        assert (
            cm.compose_file_approved(self._file(volumes=[volume]), self.MODEL) is False
        )

    def test_named_volume_backed_by_a_socket_dir_is_not_approved(self) -> None:
        doc = json.loads(self._file(volumes=["host:/h"]))
        doc["volumes"] = {"host": {"driver_opts": {"device": "/var/run"}}}
        assert cm.compose_file_approved(json.dumps(doc), self.MODEL) is False

    def test_proxy_dstack_socket_and_tmpfs_are_approved(self) -> None:
        doc = json.loads(self._file(tmpfs=["/var/run:size=4m"]))
        doc["services"]["p"] = {
            "image": "nearaidev/vllm-proxy-rs@sha256:x",
            "volumes": ["/var/run/dstack.sock:/var/run/dstack.sock", "certs:/c:ro"],
        }
        assert cm.compose_file_approved(json.dumps(doc), self.MODEL) is True

    def test_volumes_from_is_not_approved(self) -> None:
        """Inheriting another service's mounts cannot be resolved from the
        Compose program's canonical output, so it is refused outright: the
        referenced service may mount the dstack or Docker socket."""
        compose = self._file(volumes_from=["m"])
        assert cm.compose_file_approved(compose, self.MODEL) is False

    def test_tagged_proxy_with_dstack_socket_is_not_approved(self) -> None:
        """Only the digest-pinned proxy may reach the dstack socket; a
        sidecar that merely names the proxy's repository with a mutable tag
        is not provenance-verified and gets no exemption."""
        doc = json.loads(self._file())
        doc["services"]["p"] = {
            "image": "nearaidev/vllm-proxy-rs:latest",
            "volumes": ["/var/run/tappd.sock:/var/run/tappd.sock"],
        }
        assert cm.compose_file_approved(json.dumps(doc), self.MODEL) is False

    def test_sidecars_need_no_weights(self) -> None:
        compose = json.dumps(
            {
                "services": {
                    "m": {"command": f"sglang serve --model-path {self.QUANT}"},
                    "check": {
                        "image": "nearaidev/sglang@sha256:x",
                        "entrypoint": ["/usr/bin/python3", "-c"],
                        "command": ["import sys; print(sys.argv)"],
                    },
                }
            }
        )
        assert cm.model_weights_approved(compose, self.MODEL) is True


class TestVerifyInferenceAttestation:
    _GOOD_IV: Any = {
        "images": {
            "nearaidev/compose-manager@sha256:a": {
                "provenance_verified": True,
                "build_reproducible": True,
            },
            "nearaidev/vllm-proxy-rs@sha256:b": {
                "provenance_verified": True,
                "build_reproducible": True,
            },
        }
    }

    def _run(
        self,
        *,
        proxy_report_data: str = PROXY_REPORT_DATA,
        proxy_meas: dict[str, Any] | None = None,
        cm_meas: dict[str, Any] | None = None,
        image_verification: dict[str, Any] | None = None,
    ) -> Any:
        """Run the full chain with both quotes + image verification mocked."""
        proxy_meas = proxy_meas or MEAS
        cm_meas = cm_meas or MEAS
        iv = image_verification if image_verification is not None else self._GOOD_IV
        with (
            patch.object(
                cm,
                "verify_tdx_quote",
                AsyncMock(
                    side_effect=[
                        _intel_result(
                            proxy_report_data,
                            mrconfig=_boot_mrconfig(FIXTURE),
                            mrtd=proxy_meas["mrtd"],
                            rtmrs=list(proxy_meas["rtmrs"]),
                        ),
                        _intel_result(
                            REPORT_DATA,
                            # same mr_config_id as the proxy quote (same CVM)
                            mrconfig=_boot_mrconfig(FIXTURE),
                            mrtd=cm_meas["mrtd"],
                            rtmrs=list(cm_meas["rtmrs"]),
                        ),
                    ]
                ),
            ),
            patch.object(
                cm, "fetch_and_verify_serving_yaml", return_value=(True, "services: {}")
            ),
            patch.object(cm, "verify_compose_images_full", return_value=iv),
            patch.object(
                cm, "check_gpu", return_value={"nonce_matches": True, "verdict": True}
            ),
        ):
            return asyncio.run(
                cm.verify_inference_attestation(
                    FIXTURE, NONCE, _POLICY, FIXTURE["model_name"]
                )
            )

    def test_full_chain_passes_on_real_fixture(self) -> None:
        summary = self._run()
        assert summary["model_name_matches"] is True
        assert summary["tdx_verified"] is True
        assert summary["os_measurements_valid"] is True
        assert summary["mrconfig_valid"] is True
        assert summary["compose_hash_valid"] is True
        assert summary["near_images_verified"] is True
        assert summary["proxy_report_data_valid"] is True
        assert summary["same_cvm"] is True
        assert summary["report_data_valid"] is True
        assert summary["serving_yaml_verified"] is True
        assert summary["gpu_verified"] is True
        assert summary["signing_public_key"] == FIXTURE["signing_public_key"]

    def test_unreproducible_near_image_fails(self) -> None:
        bad_iv = {
            "images": {
                "nearaidev/compose-manager@sha256:a": {
                    "provenance_verified": True,
                    "build_reproducible": False,
                }
            }
        }
        summary = self._run(image_verification=bad_iv)
        assert summary["near_images_verified"] is False
        assert summary["compose_manager_verified"] is False

    def test_failing_proxy_leaves_compose_manager_verified(self) -> None:
        # A stale proxy fails the image gate, but not what the weights
        # markers rest on: the actions log's author still verified.
        iv = json.loads(json.dumps(self._GOOD_IV))
        iv["images"]["nearaidev/vllm-proxy-rs@sha256:b"]["provenance_verified"] = False
        summary = self._run(image_verification=iv)
        assert summary["near_images_verified"] is False
        assert summary["compose_manager_verified"] is True

    _OLD_PROXY = "nearaidev/vllm-proxy-rs@sha256:old"

    def test_accepted_extra_proxy_passes_beside_pinned_proxy(self) -> None:
        iv = json.loads(json.dumps(self._GOOD_IV))
        iv["images"][self._OLD_PROXY] = {
            "provenance_verified": False,
            "build_reproducible": False,
        }
        extra = {FIXTURE["model_name"]: frozenset({self._OLD_PROXY})}
        with patch.dict(cm.ACCEPTED_EXTRA_PROXY_IMAGES, extra):
            assert self._run(image_verification=iv)["near_images_verified"] is True
        assert self._run(image_verification=iv)["near_images_verified"] is False

    def test_accepted_extra_proxy_alone_fails(self) -> None:
        iv = json.loads(json.dumps(self._GOOD_IV))
        del iv["images"]["nearaidev/vllm-proxy-rs@sha256:b"]
        iv["images"][self._OLD_PROXY] = {
            "provenance_verified": False,
            "build_reproducible": False,
        }
        extra = {FIXTURE["model_name"]: frozenset({self._OLD_PROXY})}
        with patch.dict(cm.ACCEPTED_EXTRA_PROXY_IMAGES, extra):
            assert self._run(image_verification=iv)["near_images_verified"] is False

    def test_full_chain_marks_compose_manager_verified(self) -> None:
        assert self._run()["compose_manager_verified"] is True

    def test_unbound_signing_address_fails_proxy_report_data(self) -> None:
        # report_data that does not embed the signing address / nonce.
        summary = self._run(proxy_report_data="00" * 64)
        assert summary["proxy_report_data_valid"] is False
        assert summary["report_data_valid"] is False

    def test_different_cvm_measurements_fail(self) -> None:
        other = {"mrtd": "ff" * 24, "rtmrs": ["ff" * 24] * 4}
        summary = self._run(cm_meas=other)
        assert summary["same_cvm"] is False
        assert summary["report_data_valid"] is False

    def test_rtmr3_divergence_is_another_replica(self) -> None:
        # Replicas of one app share mr_td/mr_config/rtmr0-2; rtmr3 differs.
        cm_meas = {"mrtd": MEAS["mrtd"], "rtmrs": MEAS["rtmrs"][:3] + ["ee" * 24]}
        summary = self._run(cm_meas=cm_meas)
        assert summary["same_cvm"] is False
        assert summary["report_data_valid"] is False

    def test_empty_measurements_not_same_cvm(self) -> None:
        # A quote with no decoded TD measurements must not pass vacuously.
        summary = self._run(proxy_meas={"mrtd": "", "rtmrs": []})
        assert summary["same_cvm"] is False
        assert summary["report_data_valid"] is False

    def test_returns_failed_summary_when_proxy_quote_unverifiable(self) -> None:
        with patch.object(
            cm,
            "verify_tdx_quote",
            AsyncMock(side_effect=RuntimeError("quote verification failed")),
        ):
            summary = asyncio.run(
                cm.verify_inference_attestation(
                    FIXTURE, NONCE, _POLICY, FIXTURE["model_name"]
                )
            )
        assert summary["tdx_verified"] is False
        assert summary["report_data_valid"] is False
        assert summary["near_images_verified"] is False

    def test_substituted_model_fails_before_any_verification(self) -> None:
        # A different model's attestation fails closed before the quote check.
        with patch.object(cm, "verify_tdx_quote", AsyncMock()) as quote:
            summary = asyncio.run(
                cm.verify_inference_attestation(
                    FIXTURE, NONCE, _POLICY, "zai-org/GLM-5.1-FP8"
                )
            )
        quote.assert_not_called()
        assert summary["model_name_matches"] is False
        assert summary["tdx_verified"] is False
        assert summary["near_images_verified"] is False
        assert summary["model_name"] == FIXTURE["model_name"]


def _boot_mrconfig(attestation: dict) -> str:
    """Build the mrconfig (01 || compose_hash) the fixture's app_compose implies."""
    tcb = attestation["info"]["tcb_info"]
    app_compose = tcb["app_compose"]
    return ("01" + sha256(app_compose.encode()).hexdigest()).ljust(96, "0")


_APP_COMPOSE = '{"docker_compose_file": "services: {}"}'
_APP_COMPOSE_MRCONFIG = ("01" + sha256(_APP_COMPOSE.encode()).hexdigest()).ljust(
    96, "0"
)
_SERVING_SHA = "ab" * 32
_RUNNING_CM = "nearaidev/compose-manager@sha256:" + "c" * 64
_EXPECTED = cm.CvmState(
    _APP_COMPOSE,
    cm.compose_log_chain([{"action": "compose_up", "file_sha256": _SERVING_SHA}])[-1],
    _RUNNING_CM,
)
_ED25519_KEY = "40ef1aadbb12f26cf4c2d499b9e7a7b043da4388200715abed573fa135a561bb"


class TestSigningKeyFromInferenceAttestation:
    """The caller supplies the attestation; the extractor does not fetch."""

    def _att(
        self,
        algo: str = "ed25519",
        serving_sha: str = _SERVING_SHA,
        running_cm: str = _RUNNING_CM,
    ) -> dict[str, Any]:
        return {
            "signing_algo": algo,
            "signing_public_key": _ED25519_KEY,
            "signing_address": _ED25519_KEY,
            "model_name": "z-ai/glm-5.3-flash",
            "intel_quote": "deadbeef",
            "compose_manager_attestation": {
                "actions": [
                    {"action": "compose_manager_started", "image": running_cm},
                    {"action": "compose_up", "file_sha256": serving_sha},
                ]
            },
        }

    def _run(
        self,
        att: dict[str, Any],
        *,
        verified: bool,
        binds: dict,
        mrconfig: str = _APP_COMPOSE_MRCONFIG,
        cm_quote: tuple[bool, bool, bool] = (True, True, True),
        cm_mrtd: str = MEAS["mrtd"],
    ) -> Any:
        quote = _intel_result("", mrconfig=mrconfig, verified=verified)
        cm_intel = _intel_result("", mrconfig=mrconfig, mrtd=cm_mrtd)
        with (
            patch.object(cm, "verify_tdx_quote", AsyncMock(return_value=quote)),
            patch.object(cm, "check_report_data", return_value=binds),
            patch.object(
                cm,
                "_verify_compose_manager_quote",
                AsyncMock(return_value=(*cm_quote, cm_intel)),
            ),
        ):
            return asyncio.run(
                cm.signing_key_from_inference_attestation(
                    att, "nn", "ed25519", "z-ai/glm-5.3-flash", _EXPECTED
                )
            )

    _BINDS = {"binds_address": True, "binds_tls_cert": False, "embeds_nonce": True}

    def test_none_when_serving_compose_differs(self) -> None:
        # Same boot compose, but compose-manager has since swapped in another
        # serving compose the main pass never verified.
        att = self._att(serving_sha="ee" * 32)
        assert self._run(att, verified=True, binds=self._BINDS) is None

    def test_none_when_running_compose_manager_differs(self) -> None:
        att = self._att(running_cm="nearaidev/compose-manager@sha256:" + "e" * 64)
        assert self._run(att, verified=True, binds=self._BINDS) is None

    def test_none_when_actions_log_not_bound(self) -> None:
        for cm_quote in ((False, True, True), (True, False, True), (True, True, False)):
            out = self._run(
                self._att(), verified=True, binds=self._BINDS, cm_quote=cm_quote
            )
            assert out is None, cm_quote

    def test_none_when_actions_log_from_another_cvm(self) -> None:
        out = self._run(self._att(), verified=True, binds=self._BINDS, cm_mrtd="ff")
        assert out is None

    def test_none_when_cvm_runs_another_compose(self) -> None:
        # A replica booted from a compose the main pass did not verify must
        # not get its key recorded, even with a valid quote and binding.
        out = self._run(
            self._att(),
            verified=True,
            binds={"binds_address": True, "embeds_nonce": True},
            mrconfig="01" + "ee" * 47,
        )
        assert out is None

    def test_returns_key_when_binding_valid(self) -> None:
        out = self._run(
            self._att(),
            verified=True,
            binds={
                "binds_address": True,
                "binds_tls_cert": False,
                "embeds_nonce": True,
            },
        )
        assert out is not None
        assert out["signing_algo"] == "ed25519"
        assert out["signing_public_key"] == _ED25519_KEY
        assert out["model_name"] == "z-ai/glm-5.3-flash"

    def test_none_on_algo_mismatch(self) -> None:
        # Gateway signed ecdsa though ed25519 was requested -> nothing to capture.
        out = asyncio.run(
            cm.signing_key_from_inference_attestation(
                self._att("ecdsa"), "nn", "ed25519", "z-ai/glm-5.3-flash", _EXPECTED
            )
        )
        assert out is None

    def test_none_on_unverified_quote(self) -> None:
        out = self._run(
            self._att(),
            verified=False,
            binds={
                "binds_address": True,
                "binds_tls_cert": False,
                "embeds_nonce": True,
            },
        )
        assert out is None

    def test_none_when_binding_fails(self) -> None:
        out = self._run(
            self._att(),
            verified=True,
            binds={
                "binds_address": False,
                "binds_tls_cert": False,
                "embeds_nonce": True,
            },
        )
        assert out is None

    def test_none_when_nonce_not_embedded(self) -> None:
        out = self._run(
            self._att(),
            verified=True,
            binds={
                "binds_address": True,
                "binds_tls_cert": False,
                "embeds_nonce": False,
            },
        )
        assert out is None


def test_running_path_verifies_boot_launcher() -> None:
    # compose-manager self-updated, so its image comes from the actions log;
    # the launcher is not in the log and must still be verified from the
    # measured boot compose.
    launcher = "nearaidev/compose-manager-launcher@sha256:" + "f" * 64
    running = "nearaidev/compose-manager@sha256:" + "c" * 64
    boot = f"services:\n  cm:\n    image: {running}\n  l:\n    image: {launcher}\n"
    att = json.loads(json.dumps(FIXTURE))
    att["compose_manager_attestation"]["actions"].append(
        {"action": "compose_manager_started", "image": running}
    )
    full = MagicMock(return_value={"images": {}})
    with (
        patch.object(cm, "verify_tdx_quote", AsyncMock(return_value=_intel_result(""))),
        patch.object(cm, "check_report_data", return_value={}),
        patch.object(
            cm,
            "_verify_compose_manager_quote",
            AsyncMock(return_value=(True, True, True, _intel_result(""))),
        ),
        patch.object(cm, "_boot_docker_compose", return_value=boot),
        patch.object(
            cm,
            "serving_state",
            return_value={
                ("work", "m"): cm.ServingFile(
                    "c", "f.yaml", "s", "services:\n  m:\n    image: x@sha256:1\n"
                )
            },
        ),
        patch.object(cm, "verify_compose_images_full", full),
        patch.object(cm, "_verify_boot_compose_manager", return_value=(True, None)),
    ):
        asyncio.run(
            cm.verify_inference_attestation(att, NONCE, _POLICY, att["model_name"])
        )
    assert full.call_args.args[0] == ["x@sha256:1", running, launcher]


@pytest.mark.parametrize(
    "running",
    [
        "ghcr.io/x/compose-manager@sha256:" + "c" * 64,
        "nearaidev/compose-manager:latest",
    ],
    ids=["other-registry", "unpinned"],
)
def test_running_compose_manager_must_be_the_pinned_image(
    running: str, caplog: pytest.LogCaptureFixture
) -> None:
    # A decoy pinned compose-manager elsewhere must not stand in for the
    # image the log says is writing it.
    decoy = "nearaidev/compose-manager@sha256:" + "a" * 64
    att = json.loads(json.dumps(FIXTURE))
    att["compose_manager_attestation"]["actions"].append(
        {"action": "compose_manager_started", "image": running}
    )
    passing = {"provenance_verified": True, "build_reproducible": True}
    full = MagicMock(return_value={"images": {decoy: passing}})
    with (
        patch.object(cm, "verify_tdx_quote", AsyncMock(return_value=_intel_result(""))),
        patch.object(cm, "check_report_data", return_value={}),
        patch.object(
            cm,
            "_verify_compose_manager_quote",
            AsyncMock(return_value=(True, True, True, _intel_result(""))),
        ),
        patch.object(cm, "_boot_docker_compose", return_value="services: {}"),
        patch.object(
            cm,
            "serving_state",
            return_value={
                ("work", "d"): cm.ServingFile(
                    "c", "f.yaml", "s", f"services:\n  d:\n    image: {decoy}\n"
                )
            },
        ),
        patch.object(cm, "verify_compose_images_full", full),
        patch.object(cm, "_verify_boot_compose_manager", return_value=(True, None)),
    ):
        summary = asyncio.run(
            cm.verify_inference_attestation(att, NONCE, _POLICY, att["model_name"])
        )
    assert summary["compose_manager_verified"] is False
    assert summary["near_images_verified"] is False
    assert "is not a pinned nearaidev/compose-manager" in caplog.text


_W4 = (
    "/root/.cache/huggingface/hub/models--graphistry--GLM-5.3-Flash-W4AFP8"
    "/snapshots/99f1fa70408c52b007d4fd69e02e5a522422e755"
)


def _server(path: str = _W4) -> dict[str, str]:
    return {
        "image": "nearaidev/sglang@sha256:1",
        "command": f"sglang serve --model-path {path}",
    }


def _file(services: dict[str, Any], name: str | None = None) -> str:
    doc: dict[str, Any] = {"services": services}
    if name:
        doc["name"] = name
    return json.dumps(doc)


_FILES = {
    "base.yaml": _file({"r1": _server(), "r2": _server(), "nginx": {"image": "nginx"}}),
    "canary.yaml": _file(
        {"r1": _server(), "r2": _server(), "nginx": {"image": "nginx"}}
    ),
    "evil.yaml": _file({"r1": _server("/evil"), "r2": _server("/evil")}),
    "other-model.yaml": _file({"x1": _server("/other")}),
    "rotate.yaml": _file({"rotate": {"image": "alpine"}}, name="cm-token-rotate"),
}


def _up(file: str, *services: str) -> dict[str, Any]:
    return {
        "action": "compose_up",
        "commit": "c" * 40,
        "file": file,
        "file_sha256": "a" * 64,
        "services": list(services),
    }


def _down(file: str, *services: str) -> dict[str, Any]:
    return {
        "action": "compose_down",
        "commit": "c" * 40,
        "file": file,
        "services": list(services),
    }


class TestServingState:
    MODEL = "z-ai/glm-5.3-flash"

    def _state(self, *actions: dict[str, Any]) -> Any:
        with patch.object(
            cm,
            "fetch_and_verify_serving_yaml",
            side_effect=lambda commit, file, sha: (True, _FILES[file]),
        ):
            return cm.serving_state(list(actions))

    def _files(self, state: Any) -> dict[str, str]:
        return {f"{p}/{s}": f.file for (p, s), f in state.items()}

    def test_scoped_canary_replaces_only_its_service(self) -> None:
        state = self._state(_up("base.yaml"), _up("canary.yaml", "r2"))
        assert self._files(state) == {
            "work/r1": "base.yaml",
            "work/r2": "canary.yaml",
            "work/nginx": "base.yaml",
        }

    def test_up_evicts_orphans_in_the_same_project(self) -> None:
        state = self._state(_up("other-model.yaml"), _up("base.yaml"))
        assert "work/x1" not in self._files(state)

    def test_maintenance_project_leaves_models_running(self) -> None:
        state = self._state(_up("base.yaml"), _up("rotate.yaml"))
        files = self._files(state)
        assert files["cm-token-rotate/rotate"] == "rotate.yaml"
        assert files["work/r1"] == "base.yaml"
        assert cm.weights_approved(
            cm.weights_of(cm.running_services(state)), self.MODEL
        )

    def test_up_starts_what_a_service_depends_on(self) -> None:
        files = {
            "dep.yaml": _file(
                {
                    "ok": {
                        "image": "nginx",
                        "depends_on": {"mid": {"condition": "service_started"}},
                    },
                    "mid": {"image": "x", "depends_on": ["evil"]},
                    "evil": _server("/evil"),
                }
            )
        }
        with patch.object(
            cm,
            "fetch_and_verify_serving_yaml",
            side_effect=lambda commit, file, sha: (True, files[file]),
        ):
            state = cm.serving_state([_up("dep.yaml", "ok")])
        assert state is not None
        assert set(self._files(state)) == {"work/ok", "work/mid", "work/evil"}
        assert (
            cm.weights_approved(cm.weights_of(cm.running_services(state)), self.MODEL)
            is False
        )

    @pytest.mark.parametrize(
        "change",
        [{"commit": "main"}, {"commit": "C" * 40}, {"file": "../other/x.yaml"}],
        ids=["branch", "uppercase", "traversal"],
    )
    def test_unusable_log_entry_fails_closed(self, change: dict[str, str]) -> None:
        assert self._state({**_up("base.yaml"), **change}) is None

    def test_running_socket_mounts_fail_unless_maintenance(self) -> None:
        sock = {"image": "alpine", "volumes": ["/var/run/docker.sock:/s"]}
        files = {"m.yaml": _file({"rotate": sock}, name="cm-token-rotate")}
        with patch.object(
            cm,
            "fetch_and_verify_serving_yaml",
            side_effect=lambda commit, file, sha: (True, files[file]),
        ):
            state = cm.serving_state([_up("m.yaml")])
        assert state is not None
        assert cm.running_service_problems(state) == [
            "cm-token-rotate/rotate: mounts the Docker socket"
        ]
        with patch.object(cm, "APPROVED_MAINTENANCE_COMPOSES", frozenset({"a" * 64})):
            assert cm.running_service_problems(state) == []

    def test_down_removes_listed_or_all_services(self) -> None:
        assert set(
            self._files(self._state(_up("base.yaml"), _down("base.yaml", "r1")))
        ) == {
            "work/r2",
            "work/nginx",
        }
        assert self._state(_up("base.yaml"), _down("base.yaml")) == {}

    def test_unapproved_weights_behind_a_later_approved_up_fail(self) -> None:
        # New weights go to r1 only; a later approved up touches only r2.
        state = self._state(
            _up("base.yaml"), _up("evil.yaml", "r1"), _up("canary.yaml", "r2")
        )
        assert self._files(state)["work/r1"] == "evil.yaml"
        assert (
            cm.weights_approved(cm.weights_of(cm.running_services(state)), self.MODEL)
            is False
        )

    def test_unverifiable_file_or_entry_fails_closed(self) -> None:
        with patch.object(
            cm, "fetch_and_verify_serving_yaml", return_value=(False, "")
        ):
            assert cm.serving_state([_up("base.yaml")]) is None
        assert self._state({**_up("base.yaml"), "file_sha256": None}) is None

    def test_compose_file_approved_is_whole_file(self) -> None:
        assert cm.compose_file_approved(_FILES["base.yaml"], self.MODEL) is True
        assert cm.compose_file_approved(_FILES["rotate.yaml"], self.MODEL) is True
        assert cm.compose_file_approved(_FILES["evil.yaml"], self.MODEL) is False


class TestRunningGpuProblems:
    """The GPU-sidecar rule gates the verdict, not only file approval."""

    def _state(self, service: dict[str, Any], sha: str = "a" * 64) -> Any:
        return {
            ("work", "x"): cm.ServingFile(
                "c" * 40, "f.yaml", sha, _file({"x": service})
            )
        }

    @pytest.mark.parametrize(
        "extra",
        [
            {"devices": ["/dev/nvidia0:/dev/nvidia0"]},
            {"runtime": "nvidia"},
            {"privileged": True},
            {"environment": ["NVIDIA_VISIBLE_DEVICES=all"]},
            {
                "deploy": {
                    "resources": {
                        "reservations": {"devices": [{"capabilities": ["gpu"]}]}
                    }
                }
            },
        ],
        ids=[
            "device",
            "runtime",
            "privileged",
            "visible-devices",
            "reservation",
        ],
    )
    def test_gpu_sidecar_fails_the_verdict(self, extra: dict[str, Any]) -> None:
        state = self._state({"image": "alpine", **extra})
        assert cm.running_service_problems(state) == [
            "work/x: GPU access without a recognised server"
        ]

    def test_recognised_server_may_use_the_gpus(self) -> None:
        state = self._state(
            {
                "image": "nearaidev/sglang@sha256:1",
                "runtime": "nvidia",
                "command": f"sglang serve --model-path {_W4}",
            }
        )
        assert cm.running_service_problems(state) == []

    @pytest.mark.parametrize(
        "service",
        [
            {"image": "nearaidev/vllm-proxy-rs@sha256:1", "runtime": "nvidia"},
            {
                "image": "nvcr.io/nvidia/k8s/dcgm-exporter@sha256:1",
                "runtime": "nvidia",
            },
        ],
        ids=["proxy", "dcgm-exporter"],
    )
    def test_proxy_and_gpu_tools_are_exempt(self, service: dict[str, Any]) -> None:
        assert cm.running_service_problems(self._state(service)) == []

    def test_maintenance_file_is_exempt(self) -> None:
        sidecar = {"image": "alpine", "devices": ["/dev/nvidia0:/dev/nvidia0"]}
        state = self._state(sidecar)
        with patch.object(cm, "APPROVED_MAINTENANCE_COMPOSES", frozenset({"a" * 64})):
            assert cm.running_service_problems(state) == []


class TestComposeResolution:
    """Checks read files the way Docker Compose resolves them."""

    MODEL = "z-ai/glm-5.3-flash"
    SERVER = {"image": "s", "command": f"sglang serve --model-path {_W4}"}

    def _approved(self, services: dict[str, Any], **top: Any) -> bool:
        return cm.compose_file_approved(
            json.dumps({"services": services, **top}), self.MODEL
        )

    def test_baseline_is_approved(self) -> None:
        assert self._approved({"m": self.SERVER}) is True

    def test_extends_inherits_gpu_access(self) -> None:
        base = {**self.SERVER, "runtime": "nvidia"}
        helper = {"extends": "m", "command": "python run.py"}
        assert self._approved({"m": base, "helper": helper}) is False

    def test_include_of_an_unshipped_file_is_refused(self) -> None:
        assert self._approved({"m": self.SERVER}, include=["other.yaml"]) is False

    def test_yaml_1_1_name_is_still_checked(self) -> None:
        text = (
            f"services:\n  m:\n    image: s\n    command: {self.SERVER['command']}\n"
            "  no:\n    image: s\n    command: sglang serve --model-path /evil\n"
        )
        assert cm.compose_file_approved(text, self.MODEL) is False
        assert "/evil" in cm.serving_weights(text)

    def test_numeric_service_name_is_refused(self) -> None:
        text = (
            f"services:\n  010:\n    image: s\n    command: {self.SERVER['command']}\n"
        )
        assert cm.compose_file_approved(text, self.MODEL) is False

    @pytest.mark.parametrize(
        "source", ["/var//run", "/etc/../run", "//run", "../run", "~/../run"]
    )
    def test_socket_dir_paths_are_resolved(self, source: str) -> None:
        sidecar = {"image": "alpine", "volumes": [f"{source}:/r"]}
        assert self._approved({"m": self.SERVER, "x": sidecar}) is False

    @pytest.mark.parametrize(
        "extra",
        [
            {"env_file": [{"path": "e.env", "required": False}]},
            {"environment": ["NVIDIA_VISIBLE_DEVICES"]},
            {"runtime": "${R:-runc}"},
            {"privileged": "true"},
            {"deploy": {"resources": {"reservations": {"devices": [{"count": 1}]}}}},
        ],
        ids=["env-file", "pass-through", "interpolated-runtime", "string", "device"],
    )
    def test_other_gpu_forms_count(self, extra: dict[str, Any]) -> None:
        sidecar = {"image": "alpine", **extra}
        assert self._approved({"m": self.SERVER, "x": sidecar}) is False

    @pytest.mark.parametrize(
        "extra",
        [
            {"post_start": [{"command": "true"}]},
            {"pre_stop": [{"command": "true"}]},
            {"healthcheck": {"test": ["CMD", "vllm", "serve", "/evil"]}},
        ],
        ids=["post-start", "pre-stop", "healthcheck"],
    )
    def test_commands_outside_the_entrypoint(self, extra: dict[str, Any]) -> None:
        assert self._approved({"m": {**self.SERVER, **extra}}) is False

    def test_plain_healthcheck_is_approved(self) -> None:
        check = {"healthcheck": {"test": ["CMD", "curl", "-f", "localhost:8000"]}}
        assert self._approved({"m": {**self.SERVER, **check}}) is True

    @pytest.mark.parametrize(
        "flag",
        ["--speculative-config.model /evil", "--config /etc/serve.yaml"],
        ids=["dotted", "config-file"],
    )
    def test_flags_the_parser_cannot_follow(self, flag: str) -> None:
        server = {**self.SERVER, "command": f"{self.SERVER['command']} {flag}"}
        assert self._approved({"m": server}) is False

    def test_wrong_compose_version_reads_nothing(self) -> None:
        cm._compose_version_ok.cache_clear()
        cm.canonical_compose.cache_clear()
        try:
            with patch.object(cm, "COMPOSE_VERSION", "0.0.0"):
                assert cm.canonical_compose("services: {m: {image: s}}") == {}
        finally:
            cm._compose_version_ok.cache_clear()
            cm.canonical_compose.cache_clear()


def test_implicit_dependency_is_started() -> None:
    files = {
        "f.yaml": _file(
            {
                "ok": {"image": "nginx", "network_mode": "service:evil"},
                "evil": _server("/evil"),
            }
        )
    }
    with patch.object(
        cm,
        "fetch_and_verify_serving_yaml",
        side_effect=lambda commit, file, sha: (True, files[file]),
    ):
        state = cm.serving_state([_up("f.yaml", "ok")])
    assert state is not None
    assert {s for _, s in state} == {"ok", "evil"}


def test_unreadable_file_leaves_state_unknown() -> None:
    with patch.object(
        cm,
        "fetch_and_verify_serving_yaml",
        return_value=(
            True,
            json.dumps({"services": {"m": {"image": "s"}}, "include": ["x.yaml"]}),
        ),
    ):
        assert cm.serving_state([_up("f.yaml")]) is None
