# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Tests for NEAR_ENV environment selection in config.

config resolves BASE_URL and CERT_EXPECTED_COMMITS at import time from NEAR_ENV,
so each case reimports the module under a patched environment.
"""

import importlib
from collections.abc import Iterator
from types import ModuleType

import pytest

import verifier.config as config


def _reload(monkeypatch: pytest.MonkeyPatch, **env: str) -> ModuleType:
    """Reload verifier.config with the given env vars set (others cleared)."""
    for var in (
        "NEAR_ENV",
        "BASE_URL",
        "MODEL_NAME",
        "NEAR_API_KEY_PROD",
        "NEAR_API_KEY_STAGING",
        "NEAR_API_KEY",
        "API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return importlib.reload(config)


@pytest.fixture(autouse=True)
def _restore_config() -> Iterator[None]:
    """Leave the module back in its default (prod) state for other tests."""
    yield
    importlib.reload(config)


def test_default_is_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _reload(monkeypatch)
    assert c.NEAR_ENV == "prod"
    assert c.BASE_URL == "https://cloud-api.near.ai"
    assert c.CERT_EXPECTED_COMMITS["nearaidev/cloud-api"] != ""


def test_staging_switches_gateway_url(monkeypatch: pytest.MonkeyPatch) -> None:
    c = _reload(monkeypatch, NEAR_ENV="staging")
    assert c.BASE_URL == "https://cloud-stg-api.near.ai"


def test_staging_gateway_pins_are_populated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = _reload(monkeypatch, NEAR_ENV="staging")
    for image in (
        "nearaidev/cloud-api",
        "nearaidev/cvm-ingress",
        "nearaidev/dstack-vpc",
        "nearaidev/dstack-vpc-client",
    ):
        assert c.CERT_EXPECTED_COMMITS[image] != ""


def test_staging_cloud_api_pinned_independently_of_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Checks structure, not values: the two pins may hold the same commit.
    c = _reload(monkeypatch)
    pins = c._GATEWAY_EXPECTED_COMMITS
    assert pins["prod"] is not pins["staging"]
    staging = _reload(monkeypatch, NEAR_ENV="staging")
    assert (
        staging.CERT_EXPECTED_COMMITS["nearaidev/cloud-api"]
        == staging._GATEWAY_EXPECTED_COMMITS["staging"]["nearaidev/cloud-api"]
    )


def test_inference_pins_shared_across_environments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The proxy pin is per-model, so fix the model: same slug, same pins in
    # both environments.
    prod = _reload(monkeypatch, MODEL_NAME="z-ai/glm-5.3-flash")
    prod_pins = {
        k: prod.CERT_EXPECTED_COMMITS[k]
        for k in ("nearaidev/compose-manager", "nearaidev/vllm-proxy-rs")
    }
    staging = _reload(monkeypatch, NEAR_ENV="staging", MODEL_NAME="z-ai/glm-5.3-flash")
    for image, commit in prod_pins.items():
        assert staging.CERT_EXPECTED_COMMITS[image] == commit
        assert commit != ""


def test_proxy_pin_selected_by_model_id(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _reload(monkeypatch)
    assert (
        cfg._proxy_pin("z-ai/glm-5.3-flash")
        == cfg._PROXY_EXPECTED_COMMITS["z-ai/glm-5.3-flash"]
    )
    # An unknown model yields no pin, which fails closed at the image check.
    assert cfg._proxy_pin("zai-org/GLM-5.1-FP8") == ""
    assert cfg._proxy_pin("") == ""


def test_model_name_selects_the_proxy_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    known = _reload(monkeypatch, MODEL_NAME="z-ai/glm-5.3-flash")
    assert known.CERT_EXPECTED_COMMITS["nearaidev/vllm-proxy-rs"] != ""
    unknown = _reload(monkeypatch, MODEL_NAME="zai-org/GLM-5.1-FP8")
    assert unknown.CERT_EXPECTED_COMMITS["nearaidev/vllm-proxy-rs"] == ""


def test_explicit_base_url_overrides_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = _reload(monkeypatch, NEAR_ENV="staging", BASE_URL="https://example.test")
    assert c.BASE_URL == "https://example.test"


def test_api_key_selects_per_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # CodeBuild supplies both keys. The verifier picks by NEAR_ENV.
    prod = _reload(monkeypatch, NEAR_API_KEY_PROD="pk", NEAR_API_KEY_STAGING="sk")
    assert prod.API_KEY == "pk"
    staging = _reload(
        monkeypatch,
        NEAR_ENV="staging",
        NEAR_API_KEY_PROD="pk",
        NEAR_API_KEY_STAGING="sk",
    )
    assert staging.API_KEY == "sk"


def test_api_key_falls_back_to_single_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # No per-env key set: fall back to a single NEAR_API_KEY, then API_KEY.
    assert _reload(monkeypatch, NEAR_API_KEY="one").API_KEY == "one"
    assert _reload(monkeypatch, API_KEY="legacy").API_KEY == "legacy"


def test_api_key_empty_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _reload(monkeypatch).API_KEY == ""


def test_unknown_environment_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="Unknown NEAR_ENV"):
        _reload(monkeypatch, NEAR_ENV="qa")
