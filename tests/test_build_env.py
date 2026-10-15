# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""The reproducible rebuild runs the build script with the deployed image's CI
build-arg env."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from verifier.config import CERT_BUILD_ENV
from verifier.verifications.image import _run_build_script


def _fake_completed(returncode: int = 0) -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = ""
    proc.stderr = ""
    return proc


def _fake_build(*_args: object, cwd: Path, **_kwargs: object) -> MagicMock:
    """A build that writes oci.tar, as the real script does."""
    (Path(cwd) / "oci.tar").write_bytes(b"stub")
    return _fake_completed()


def test_build_env_passed_to_subprocess(tmp_path: Path) -> None:
    script = tmp_path / "build-image.sh"
    script.write_text("#!/bin/bash\n")

    with patch(
        "verifier.verifications.image.subprocess.run",
        side_effect=_fake_build,
    ) as run:
        ok = _run_build_script(script, tmp_path, {"ENABLE_NV_ATTESTATION_SDK": "1"})

    assert ok
    env = run.call_args.kwargs["env"]
    assert env["ENABLE_NV_ATTESTATION_SDK"] == "1"
    assert env["SOURCE_DATE_EPOCH"] == "0"


def test_no_build_env_leaves_base_env(tmp_path: Path) -> None:
    script = tmp_path / "build-image.sh"
    script.write_text("#!/bin/bash\n")

    with patch(
        "verifier.verifications.image.subprocess.run",
        side_effect=_fake_build,
    ) as run:
        _run_build_script(script, tmp_path, None)

    env = run.call_args.kwargs["env"]
    assert "ENABLE_NV_ATTESTATION_SDK" not in env
    assert env["SOURCE_DATE_EPOCH"] == "0"


def test_proxy_build_env_configured() -> None:
    assert CERT_BUILD_ENV["nearaidev/vllm-proxy-rs"] == {
        "ENABLE_NV_ATTESTATION_SDK": "1"
    }


def test_build_does_not_inherit_secrets(tmp_path: Path) -> None:
    """The rebuild runs third-party code; it must not see our credentials."""
    script = tmp_path / "build-image.sh"
    script.write_text("#!/bin/bash\n")
    secrets_env = {
        "NEAR_API_KEY_PROD": "k",
        "AWS_SECRET_ACCESS_KEY": "s",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/creds",
        "NEAR_BUCKET_NAME": "b",
        "PATH": "/usr/bin",
    }
    with (
        patch.dict("os.environ", secrets_env, clear=True),
        patch(
            "verifier.verifications.image.subprocess.run",
            side_effect=_fake_build,
        ) as run,
    ):
        _run_build_script(script, tmp_path, None)

    env = run.call_args.kwargs["env"]
    assert env["PATH"] == "/usr/bin"
    assert not {"NEAR_API_KEY_PROD", "NEAR_BUCKET_NAME"} & env.keys()
    assert not [k for k in env if k.startswith("AWS_")]
