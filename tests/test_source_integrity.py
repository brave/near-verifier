# Copyright (c) 2026 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""The rebuild must use the audited commit and a digest the build produced."""

import io
import json
import subprocess
import tarfile
from hashlib import sha256
from pathlib import Path

from verifier.verifications import image


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()


def test_branch_named_like_the_commit_is_not_the_commit(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "f").write_text("audited")
    _git(tmp_path, "add", "f")
    _git(tmp_path, "commit", "-qm", "audited")
    audited = _git(tmp_path, "rev-parse", "HEAD")
    assert image._checked_out(tmp_path, audited)

    (tmp_path / "f").write_text("other")
    _git(tmp_path, "commit", "-qam", "other")
    # A branch named after the audited SHA wins over the commit in checkout.
    _git(tmp_path, "branch", audited)
    _git(tmp_path, "checkout", "-q", audited)
    assert not image._checked_out(tmp_path, audited)


def _oci(path: Path, blobs: dict[str, bytes], index_digest: str) -> None:
    with tarfile.open(path, "w") as tar:
        files = {"index.json": json.dumps({"manifests": [{"digest": index_digest}]})}
        files.update({f"blobs/sha256/{k}": v for k, v in blobs.items()})  # type: ignore[misc]
        for name, data in files.items():
            raw = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))


def _blob(data: bytes) -> tuple[str, bytes]:
    return sha256(data).hexdigest(), data


def test_oci_digest_needs_matching_blobs(tmp_path: Path) -> None:
    layer_hex, layer = _blob(b"layer bytes")
    config_hex, config = _blob(b"{}")
    manifest = json.dumps(
        {
            "config": {"digest": f"sha256:{config_hex}"},
            "layers": [{"digest": f"sha256:{layer_hex}"}],
        }
    ).encode()
    manifest_hex, _ = _blob(manifest)
    good = {manifest_hex: manifest, config_hex: config, layer_hex: layer}
    oci = tmp_path / "oci.tar"

    _oci(oci, good, f"sha256:{manifest_hex}")
    assert image._extract_digest_from_oci(oci) == f"sha256:{manifest_hex}"

    # index.json naming a digest with no blob behind it.
    _oci(oci, {}, f"sha256:{'a' * 64}")
    assert image._extract_digest_from_oci(oci) == ""

    # A layer whose bytes do not match the manifest.
    _oci(oci, {**good, layer_hex: b"tampered"}, f"sha256:{manifest_hex}")
    assert image._extract_digest_from_oci(oci) == ""

    # A missing layer.
    _oci(oci, {manifest_hex: manifest, config_hex: config}, f"sha256:{manifest_hex}")
    assert image._extract_digest_from_oci(oci) == ""


def test_cached_clone_is_reset_to_the_commit(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "f").write_text("audited")
    _git(tmp_path, "add", "f")
    _git(tmp_path, "commit", "-qm", "audited")
    audited = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "f").write_text("tampered")
    (tmp_path / "extra.sh").write_text("echo injected")
    assert image._reset_clone(tmp_path, audited)
    assert (tmp_path / "f").read_text() == "audited"
    assert not (tmp_path / "extra.sh").exists()
