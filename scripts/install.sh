#!/bin/bash
# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
set -euo pipefail

echo "Installing dependencies for TEE verification..."
pip3 install "pip==26.2.1"
pip3 install "poetry==2.3.4"
poetry install --no-interaction --no-ansi

echo "Installing jq..."
JQ_VERSION="${JQ_VERSION:-1.7.1}"
JQ_SHA256="${JQ_SHA256:-5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5}"
dnf install -y jq 2>/dev/null || {
    echo "Installing jq ${JQ_VERSION} from GitHub..."
    curl -fL -o /usr/local/bin/jq \
        "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-amd64"
    JQ_ACTUAL_SHA="$(sha256sum /usr/local/bin/jq | awk '{print $1}')"
    if [ "$JQ_SHA256" != "$JQ_ACTUAL_SHA" ]; then
        echo "❌ jq ${JQ_VERSION} checksum mismatch (expected=$JQ_SHA256 actual=$JQ_ACTUAL_SHA)"
        exit 1
    fi
    chmod +x /usr/local/bin/jq
    echo "✅ jq ${JQ_VERSION} verified (sha256=$JQ_ACTUAL_SHA)"
}

echo "Installing cosign..."
# v3.x is required: older cosign does not resolve OCI 1.1 referrers.
COSIGN_VERSION="${COSIGN_VERSION:-v3.0.6}"
COSIGN_SHA256="${COSIGN_SHA256:-c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74}"
COSIGN_BASE="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}"
curl -fL -o /usr/local/bin/cosign "${COSIGN_BASE}/cosign-linux-amd64"
EXPECTED_SHA="$COSIGN_SHA256"
ACTUAL_SHA="$(sha256sum /usr/local/bin/cosign | awk '{print $1}')"
if [ -z "$EXPECTED_SHA" ] || [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "❌ cosign ${COSIGN_VERSION} checksum mismatch (expected=$EXPECTED_SHA actual=$ACTUAL_SHA)"
    exit 1
fi
chmod +x /usr/local/bin/cosign
echo "✅ cosign ${COSIGN_VERSION} verified (sha256=$ACTUAL_SHA)"

echo "Installing Docker Compose..."
# The verifier reads compose files through `docker compose config`, pinned to
# the version compose-manager runs (verifier/config.py COMPOSE_VERSION).
COMPOSE_VERSION="${COMPOSE_VERSION:-v5.1.4}"
COMPOSE_SHA256="${COMPOSE_SHA256:-33b208d7e76639db742fae84b966cc01dacae58ca3fc4dabbc907045aefdf0c4}"
COMPOSE_DIR=/usr/local/lib/docker/cli-plugins
mkdir -p "$COMPOSE_DIR"
curl -fL -o "$COMPOSE_DIR/docker-compose" \
    "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-x86_64"
ACTUAL_SHA="$(sha256sum "$COMPOSE_DIR/docker-compose" | awk '{print $1}')"
if [ "$COMPOSE_SHA256" != "$ACTUAL_SHA" ]; then
    echo "❌ Docker Compose ${COMPOSE_VERSION} checksum mismatch (expected=$COMPOSE_SHA256 actual=$ACTUAL_SHA)"
    exit 1
fi
chmod +x "$COMPOSE_DIR/docker-compose"
echo "✅ Docker Compose ${COMPOSE_VERSION} verified (sha256=$ACTUAL_SHA)"

# Build scripts use skopeo only to print or push the digest, which does not
# affect oci.tar. It isn't packaged on Amazon Linux 2023, so fall back to a stub.
echo "Installing skopeo..."
if dnf install -y skopeo 2>/dev/null || yum install -y skopeo 2>/dev/null; then
    echo "✅ skopeo installed"
else
    echo "⚠️ skopeo unavailable, installing a no-op stub (digest comes from oci.tar)"
    cat > /usr/local/bin/skopeo <<'SKOPEO_STUB'
#!/bin/sh
# No-op skopeo. The verifier reproduces images via 'docker buildx build
# --output type=oci' and hashes oci.tar directly; build scripts only use skopeo
# to print the digest or push, which do not affect oci.tar. Refuse 'copy' so the
# stub can never silently publish; emit empty JSON for everything else so a
# 'skopeo inspect | jq' in a build script stays quiet.
case "$1" in
  copy) echo "skopeo stub: 'copy' (push) is not supported in the verifier" >&2; exit 1 ;;
  *) echo '{}' ;;
esac
exit 0
SKOPEO_STUB
    chmod +x /usr/local/bin/skopeo
fi

echo "Installing git..."
dnf install -y git 2>/dev/null || yum install -y git

echo "Configuring git for GPG commit verification..."
git config --global gpg.format openpgp
which gpg || {
    echo "Installing gnupg..."
    dnf install -y gnupg 2>/dev/null || yum install -y gnupg
}

# GitHub's key
gpg --import << 'EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=uMz0
-----END PGP PUBLIC KEY BLOCK-----
EOF

# 6 = ultimate trust; ownertrust needs the full 40-hex fingerprint.
echo "968479A1AFF927E37D1A566BB5690EEEBB952194:6:" | gpg --import-ownertrust

echo "✅ GPG keys imported and configured"

echo "Verifying installations..."
python3 --version
docker --version
cosign version
docker compose version
git --version
jq --version
skopeo --version 2>/dev/null || echo "skopeo: no-op stub (the digest comes from oci.tar)"

echo "✅ All dependencies installed successfully"
