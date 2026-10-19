# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Configuration constants for attestation verification."""

import os

# prod and staging have separate gateway deployments (separate commit pins) but
# share the inference CVMs.
NEAR_ENV: str = os.environ.get("NEAR_ENV", "prod").strip().lower()

_ENVIRONMENT_BASE_URLS: dict[str, str] = {
    "prod": "https://cloud-api.near.ai",
    "staging": "https://cloud-stg-api.near.ai",
}
if NEAR_ENV not in _ENVIRONMENT_BASE_URLS:
    raise ValueError(
        f"Unknown NEAR_ENV={NEAR_ENV!r}; expected one of "
        f"{sorted(_ENVIRONMENT_BASE_URLS)}"
    )

BASE_URL: str = os.environ.get("BASE_URL", _ENVIRONMENT_BASE_URLS[NEAR_ENV])
# The API key is sent as a bearer token and the TLS check needs a live cert, so
# a plain-http override would leak the key and leave nothing to verify.
if not BASE_URL.startswith("https://"):
    raise ValueError(f"BASE_URL must be https://, got {BASE_URL!r}")
API_KEY: str = (
    os.environ.get(f"NEAR_API_KEY_{NEAR_ENV.upper()}", "")
    or os.environ.get("NEAR_API_KEY", "")
    or os.environ.get("API_KEY", "")
)

# Signing schemes swept per run (the endpoint signs with one per request).
#   - ecdsa:   signing_address = keccak-256(secp256k1 pubkey)[-20:]
#   - ed25519: signing_address == signing_public_key (raw 32 bytes)
SIGNING_ALGOS: tuple[str, ...] = ("ecdsa", "ed25519")

GPU_VERIFIER_API: str = "https://nras.attestation.nvidia.com/v3/attest/gpu"
NVIDIA_JWKS_URL: str = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
PCCS_URL: str = "https://api.trustedservices.intel.com"

# A TDX quote whose status is "OutOfDate" is accepted only when every advisory
# it reports is listed here. These four are the ones NEAR's production host
# reports: the attestation is valid but the host runs older Intel firmware.
# Remove entries once the host firmware is updated; never add one without
# review.
ACCEPTED_OUTOFDATE_ADVISORIES: frozenset[str] = frozenset(
    {"INTEL-SA-01192", "INTEL-SA-01245", "INTEL-SA-01312", "INTEL-SA-01313"}
)

# Docker Compose resolves every compose file the checks read, so they see what
# compose-manager runs. Pin the version compose-manager's image installs
# (docker-compose-plugin in its Dockerfile at the pinned commit). COMPOSE_BIN
# points at a standalone docker-compose binary instead of the docker plugin.
COMPOSE_VERSION: str = "5.1.4"
COMPOSE_COMMAND: tuple[str, ...] = (
    (os.environ["COMPOSE_BIN"],)
    if os.environ.get("COMPOSE_BIN")
    else ("docker", "compose")
)

# Marketplace model id verified this run; also selects the per-model proxy pin.
MODEL_NAME: str = os.environ.get("MODEL_NAME", "z-ai/glm-5.3-flash")

# Repo of the compose YAMLs compose-manager pulls; their sha256 must match the
# verified actions log.
CVM_COMPOSE_FILES_REPO: str = "nearai/cvm-compose-files"
CVM_COMPOSE_FILES_RAW_BASE: str = "https://raw.githubusercontent.com"

# NEAR-authored inference-CVM images. Kept separate from CERT_REPOSITORIES so
# they are not required images of the gateway compose. The third-party model
# runtime image is bound via the actions log instead.
#   - compose-manager: signs the actions log (root of trust for model swaps)
#   - compose-manager-launcher: pinned in the measured boot compose; picks
#     which compose-manager image runs, including after a reboot
INFERENCE_REPOSITORIES: dict[str, str] = {
    "nearaidev/compose-manager": "nearai/compose-manager",
    "nearaidev/compose-manager-launcher": "nearai/compose-manager",
    "nearaidev/vllm-proxy-rs": "nearai/inference-proxy",
}

# Image name prefix → cosign --certificate-identity-regexp. Any ref is allowed;
# the commit is pinned via the provenance (CERT_EXPECTED_COMMITS).
# Anchored because cosign does an unanchored RE2 match, so a SAN merely
# containing the string would otherwise pass.
CERT_IDENTITY_REGEXP: dict[str, str] = {
    "nearaidev/cloud-api": (
        r"^https://github\.com/nearai/cloud-api/"
        r"\.github/workflows/build\.yml@refs/.*$"
    ),
    # TLS-terminating sidecar in the same CVM as cloud-api.
    "nearaidev/cvm-ingress": (
        r"^https://github\.com/nearai/cvm-ingress/"
        r"\.github/workflows/build-push\.yml@refs/.*$"
    ),
    "nearaidev/dstack-vpc": (
        r"^https://github\.com/nearai/dstack-vpc/"
        r"\.github/workflows/build\.yml@refs/.*$"
    ),
    "nearaidev/dstack-vpc-client": (
        r"^https://github\.com/nearai/dstack-vpc-client/"
        r"\.github/workflows/build\.yml@refs/.*$"
    ),
    # Inference-CVM images (see INFERENCE_REPOSITORIES).
    "nearaidev/compose-manager": (
        r"^https://github\.com/nearai/compose-manager/"
        r"\.github/workflows/build\.yml@refs/.*$"
    ),
    "nearaidev/compose-manager-launcher": (
        r"^https://github\.com/nearai/compose-manager/"
        r"\.github/workflows/build\.yml@refs/.*$"
    ),
    "nearaidev/vllm-proxy-rs": (
        r"^https://github\.com/nearai/inference-proxy/"
        r"\.github/workflows/build\.yml@refs/.*$"
    ),
}
CERT_OIDC_ISSUER: str = "https://token.actions.githubusercontent.com"

# Image name prefix → the exact audited git commit accepted. An empty string
# fails closed.
_GATEWAY_EXPECTED_COMMITS: dict[str, dict[str, str]] = {
    # Sigstore-verified from the deployed images' provenance.
    "prod": {
        "nearaidev/cloud-api": "752e2976a7ee2a8790163974ba4a70dd218bbf3b",
        "nearaidev/cvm-ingress": "6b1b58c9cf63ada80cb3be7456fbedcae9cf0173",
        "nearaidev/dstack-vpc": "12a5f4e1ebe87d31dba42cc246bb8761e6fcdfa6",
        "nearaidev/dstack-vpc-client": "e0b365cea0af0943cda7b0456e00108c8d768be7",
    },
    # From cloud-stg-api.near.ai.
    "staging": {
        "nearaidev/cloud-api": "752e2976a7ee2a8790163974ba4a70dd218bbf3b",
        "nearaidev/cvm-ingress": "c785c6ed8d4ec0bb0ec4bcb45ef7afe3de48b24e",
        "nearaidev/dstack-vpc": "12a5f4e1ebe87d31dba42cc246bb8761e6fcdfa6",
        "nearaidev/dstack-vpc-client": "e0b365cea0af0943cda7b0456e00108c8d768be7",
    },
}

# vllm-proxy-rs pins, keyed by marketplace model id (each model's compose pins
# its own proxy build). List only models NEAR currently serves: review_pins.py
# runs once per entry.
_PROXY_EXPECTED_COMMITS: dict[str, str] = {
    "z-ai/glm-5.3-flash": "0f37728af5387d4805a12db133662d769a679373",
}


# Hugging Face snapshots ("org/name@revision") a human has approved, keyed by
# marketplace model id. Every model path, chat template, tokenizer and draft
# model in the serving compose must resolve to one of these; an unlisted repo
# or revision, a path that is not a pinned snapshot, or no model path at all
# fails closed.
APPROVED_MODEL_WEIGHTS: dict[str, frozenset[str]] = {
    "z-ai/glm-5.3-flash": frozenset(
        {
            # Z.ai's release.
            "zai-org/GLM-5.3-Flash@84c6a6aa9497188e15a635ba793b0f95a79b1033",
            # Z.ai's next commit; only chat_template.jinja differs from the
            # one above. The W4AFP8 files load their --chat-template from it.
            "zai-org/GLM-5.3-Flash@3f1971b7b5f7a528c9c4ef6212c8785298a8c24a",
            # Third-party 4-bit quantization of it, served by the W4AFP8 files.
            "graphistry/GLM-5.3-Flash-W4AFP8@99f1fa70408c52b007d4fd69e02e5a522422e755",
        }
    ),
}


# Exact vllm-proxy-rs images accepted beside the pinned proxy, keyed by
# marketplace model id. 98b57ad7 (ee53bec) appears in the compose-manager log
# as an artifact of an old release (project glm53-hicache-gpu03). A pinned
# proxy must still be present and pass.
ACCEPTED_EXTRA_PROXY_IMAGES: dict[str, frozenset[str]] = {
    "z-ai/glm-5.3-flash": frozenset(
        {
            "nearaidev/vllm-proxy-rs@sha256:"
            "98b57ad7aa4f9afd8ffff3ac9f4773303997f667e1d221be076c2f064e4a1284",
        }
    ),
}


# sha256 of reviewed maintenance compose files whose services may reach the
# Docker socket. Such a socket can start any container, so a file that mounts
# it is approved only when listed here.
APPROVED_MAINTENANCE_COMPOSES: frozenset[str] = frozenset(
    {
        # prod/rotate-compose-manager-token.yaml at nearai/cvm-compose-files
        # 3c2f033b: docker exec into the launcher to rotate BEARER_TOKEN.
        "0d1263e5169ebacdb1da157857aafff9a5bb5645aabbd921b3bd7e18d60a8ee2",
    }
)


def _proxy_pin(model: str) -> str:
    """The vllm-proxy-rs pin for this model; "" (fail closed) if unknown."""
    return _PROXY_EXPECTED_COMMITS.get(model, "")


# compose-manager self-updates, so its pin is checked against the running image
# from the latest compose_manager_started action, not the boot compose.
_INFERENCE_EXPECTED_COMMITS: dict[str, str] = {
    "nearaidev/compose-manager": "8cf272a67671fa1d8ff09613a2de83194f27e06f",
    "nearaidev/compose-manager-launcher": "8e07c3583909c9ab9da94d883e87add1ae90832d",
    "nearaidev/vllm-proxy-rs": _proxy_pin(MODEL_NAME),
}

# compose-manager commits a human has reviewed for booting an inference CVM.
# The boot build is the hardware-measured root that decides which
# compose-manager runs next and so vouches for the actions log; an unlisted
# commit fails closed and the error names it. Review it for honest logging.
BOOT_COMPOSE_MANAGER_COMMITS: frozenset[str] = frozenset(
    {
        "8cf272a67671fa1d8ff09613a2de83194f27e06f",
    }
)

CERT_EXPECTED_COMMITS: dict[str, str] = {
    **_INFERENCE_EXPECTED_COMMITS,
    **_GATEWAY_EXPECTED_COMMITS[NEAR_ENV],
}

# Image name prefix → GitHub owner/repo (derives allowed_builders).
CERT_REPOSITORIES: dict[str, str] = {
    "nearaidev/cloud-api": "nearai/cloud-api",
    "nearaidev/cvm-ingress": "nearai/cvm-ingress",
    "nearaidev/dstack-vpc": "nearai/dstack-vpc",
    "nearaidev/dstack-vpc-client": "nearai/dstack-vpc-client",
}

# Images exempt from the reproducible-build check, verified by pinned
# provenance only.
#   - compose-manager-launcher: NEAR's CI builds it with wall-clock timestamps
#     and unpinned `apk add` packages, so no rebuild can match its digest.
CERT_SKIP_REPRODUCIBILITY: set[str] = {"nearaidev/compose-manager-launcher"}

# Env vars the repo's build script needs to match production CI's build.
#   - vllm-proxy-rs: CI sets ENABLE_NV_ATTESTATION_SDK=1; build-image.sh
#     defaults it to 0.
CERT_BUILD_ENV: dict[str, dict[str, str]] = {
    "nearaidev/vllm-proxy-rs": {"ENABLE_NV_ATTESTATION_SDK": "1"},
}

# Allowed dstack OS measurements, as (MRTD, RTMR0, RTMR1, RTMR2) hex tuples.
# MR_CONFIG_ID is host-chosen; only the genuine dstack OS ties it to the compose
# hash, so without pinning the OS any TDX host could boot its own TD with a
# legitimate MR_CONFIG_ID. RTMR0 varies with VM shape, so a release may need
# several entries.
# The prod gateway and inference tuples were reproduced with dstack-mr
# (Dstack-TEE/dstack v0.5.11) from the meta-dstack release images whose
# os_image_hash the CVMs attest, using each CVM's attested vm_config. The
# staging tuple is observed from DCAP-verified quotes only.
EXPECTED_OS_MEASUREMENTS: frozenset[tuple[str, str, str, str]] = frozenset(
    {
        # prod gateway (cloud-api.near.ai), dstack-0.5.4
        (
            "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
            "fb14dc139f33d6fcf474bc8332cac001259fb31cfbcb6b34d4ceeb552a2c4466884a0cbde45ad98a05c5c060c23ad65a",
            "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
            "24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe",
        ),
        # staging gateway (cloud-stg-api.near.ai)
        (
            "7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
            "d090162bff4b1d1dc74dc59dc548838efc4b811b173da8536efa8e2a9c045da70ee092301293ad90afebee448bcd0211",
            "ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726",
            "ad1ed113dbecf8516b1ae1ba33a5188d61dd4a4baf5c181c1dd3c61ed8b91a624b5ac2242328028e540d9a2fb4f2dbfe",
        ),
        # inference CVM, shared by prod and staging (z-ai/glm-5.3-flash),
        # dstack-nvidia-0.5.11
        (
            "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b",
            "bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590",
            "ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726",
            "4d662c04766145dfe084fd014969b19c387afe9bb1d4f972c6968d28a7a8b4937c414603a2cf446105eddce67a86f9ce",
        ),
    }
)  # fmt: skip

# S3 key prefix for pre-verified image results (PRE_VERIFY_DISABLED=1 to bypass).
PRE_VERIFY_KEY_PREFIX: str = "pre-verified/"

# S3 key prefix for signing-key markers; the object's presence is the stamp.
SIGNING_KEY_KEY_PREFIX: str = "signing-keys/"

# S3 key prefix for approved serving composes: <prefix><model>/<sha256>.json,
# the sha256 being the compose_up file_sha256 from the actions log. The relay
# checks the live log against it, so a compose the verifier has not approved
# (and so any change of model weights) is refused.
SERVING_COMPOSE_KEY_PREFIX: str = "serving-compose/"

# S3 key prefix for verified compose histories: <prefix><model>/<head>.json,
# head being compose_log_chain's last entry for a CVM that passed. The relay
# finds the newest such head in the live log and requires every compose_up
# after it to have a serving-compose marker.
SERVING_LOG_KEY_PREFIX: str = "serving-log/"
