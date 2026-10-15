#!/bin/bash
# Copyright (c) 2025 The Brave Authors. All rights reserved.
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.
# Local test script - runs verification without CodeBuild container
# Usage: ./test-local.sh [--verbose] [--skip-setup]
# Not `-o pipefail`: the GPG fingerprint check pipes through grep, which exits
# 1 on no-match.
set -eu

VERBOSE=false
SKIP_SETUP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --skip-setup|--no-setup|-s)
            SKIP_SETUP=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--skip-setup]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose      Show detailed output"
            echo "  -s, --skip-setup   Skip Python environment setup (faster for repeated runs)"
            echo ""
            echo "Examples:"
            echo "  $0                 # First run - full setup"
            echo "  $0 --skip-setup    # Subsequent runs - skip setup"
            echo "  $0 -v -s           # Verbose mode, skip setup"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--verbose] [--skip-setup]"
            exit 1
            ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_status() { echo -e "${BLUE}▶${NC} $1"; }
print_section() { 
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${BLUE}$1${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="/tmp/verify-near-tee-test"
VERIFICATION_DIR="$WORK_DIR/verification"
VENV_DIR="$WORK_DIR/venv"
# Throwaway keyring so the GitHub key import never touches ~/.gnupg; exported
# for `git verify-commit` in the verification run.
export GNUPGHOME="$WORK_DIR/gnupg"

cleanup() {
    gpgconf --kill gpg-agent 2>/dev/null || true
    if [ "$VERBOSE" = false ]; then
        echo ""
        print_status "Cleaning up (the venv and keyring stay for --skip-setup)..."
        rm -rf "$VERIFICATION_DIR"
    else
        echo ""
        print_status "Work directory preserved at: $WORK_DIR"
    fi
}

trap cleanup EXIT

if [ "$SKIP_SETUP" = false ]; then
    print_section "📋 Checking Prerequisites"

    check_command() {
        if command -v "$1" &> /dev/null; then
            print_info "$1: $(command -v $1)"
            return 0
        else
            print_error "$1: not found"
            return 1
        fi
    }

    MISSING=false
    check_command python3 || MISSING=true
    check_command docker || MISSING=true
    check_command git || MISSING=true
    check_command gpg || MISSING=true
    check_command curl || MISSING=true
    check_command poetry || MISSING=true
    check_command cosign || MISSING=true
    if [ -z "${COMPOSE_BIN:-}" ] && ! docker compose version &> /dev/null; then
        print_error "docker compose: not found (or set COMPOSE_BIN)"
        MISSING=true
    fi

    if [ "$MISSING" = true ]; then
        print_error "Missing required dependencies"
        echo ""
        echo "Install missing dependencies:"
        echo "  macOS:   brew install python3 docker git gnupg curl poetry cosign"
        echo "  Ubuntu:  sudo apt install python3 python3-venv docker.io git gnupg curl"
        echo "  Fedora:  sudo dnf install python3 docker git gnupg2 curl"
        echo "  poetry:  https://python-poetry.org/docs/#installation"
        echo "  cosign:  https://docs.sigstore.dev/cosign/system_config/installation/"
        exit 1
    fi

    if command -v curl &> /dev/null; then
        print_status "Downloading and importing GitHub GPG key..."
        mkdir -p "$GNUPGHOME"
        chmod 700 "$GNUPGHOME"
        if curl -fsSL https://github.com/web-flow.gpg | gpg --import; then
            print_info "GitHub GPG key imported"

            IMPORTED_KEY=$(gpg --list-keys --with-colons B5690EEEBB952194 2>/dev/null | grep "^fpr" | cut -d: -f10 | head -1)
            EXPECTED_KEY="968479A1AFF927E37D1A566BB5690EEEBB952194"

            if [ "$IMPORTED_KEY" != "$EXPECTED_KEY" ]; then
                print_error "GitHub GPG key fingerprint mismatch!"
                print_error "Expected: $EXPECTED_KEY"
                print_error "Got:      $IMPORTED_KEY"
                exit 1
            fi

            echo "$IMPORTED_KEY:6:" | gpg --import-ownertrust
            print_info "✅ GitHub GPG key imported and verified"
        else
            print_error "Failed to import GitHub GPG key"
            exit 1
        fi
    else
        print_error "curl not found"
        exit 1
    fi

    print_section "🐍 Setting Up Python Environment"

    if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
        print_info "Virtual environment already exists"
    else
        print_status "Creating virtual environment..."
        python3 -m venv "$VENV_DIR"
    fi

    print_status "Activating virtual environment..."
    source "$VENV_DIR/bin/activate"

    print_status "Checking pip version..."
    if python3 -m pip install --upgrade pip --dry-run 2>&1 | grep -q "already satisfied"; then
        print_info "Pip already up to date"
    else
        print_status "Upgrading pip..."
        pip install --upgrade pip --quiet
        print_info "Pip upgraded"
    fi

    print_status "Checking Python packages..."
    poetry install
    print_info "Python environment ready"
    python3 --version
else
    print_section "⚡ Skipping Python Setup"

    if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
        print_status "Activating existing virtual environment..."
        source "$VENV_DIR/bin/activate"
        print_info "Virtual environment activated"
        python3 --version
        if [ ! -d "$GNUPGHOME" ]; then
            print_warning "GPG keyring not found at $GNUPGHOME; commit signature checks will fail"
        fi
    else
        print_error "Virtual environment not found at $VENV_DIR"
        print_warning "Run without --skip-setup first to create the environment"
        exit 1
    fi
fi

if [ -f "$SCRIPT_DIR/.env.local" ]; then
    print_status "Loading environment variables..."
    set -a
    source "$SCRIPT_DIR/.env.local"
    set +a
    print_info "Environment loaded"
else
    print_warning "No .env.local file found"
fi

print_section "🔧 Setting Up Workspace"
mkdir -p "$VERIFICATION_DIR"

print_status "Copying verification modules..."
cp -r "$SCRIPT_DIR/verifier" "$VERIFICATION_DIR/"
cp -r "$SCRIPT_DIR/scripts" "$VERIFICATION_DIR/scripts"
print_info "Modules copied to $VERIFICATION_DIR/verifier"

export PYTHONPATH="$VERIFICATION_DIR:${PYTHONPATH:-}"

print_section "🔍 Running Verification"
print_status "Testing model: ${MODEL_NAME:-z-ai/glm-5.3-flash}"

cd "$VERIFICATION_DIR"

set +e
python3 -u -m verifier.main 2>&1 | tee verification-output.log
# PIPESTATUS[0] is python's status; $? would be tee's.
EXIT_CODE=${PIPESTATUS[0]}
set -e

print_status "Script exit code: $EXIT_CODE"

if [ -f verification-output.log ]; then
    LINE_COUNT=$(wc -l < verification-output.log)
    BYTE_COUNT=$(wc -c < verification-output.log)
    print_info "Log file: $LINE_COUNT lines, $BYTE_COUNT bytes"
else
    print_error "No log file created!"
fi

print_section "📊 Final Report"

REPORT_FILE="$VERIFICATION_DIR/final-report.txt"
cat > "$REPORT_FILE" << REPORT_HEADER
================================================================================
TEE VERIFICATION REPORT
================================================================================
Build Time: $(date)
Test Type: Local (without CodeBuild)
Work Directory: $WORK_DIR
================================================================================
VERIFICATION SUMMARY
================================================================================
REPORT_HEADER

if [ -f "$VERIFICATION_DIR/verification-output.log" ]; then
    cat "$VERIFICATION_DIR/verification-output.log" >> "$REPORT_FILE"
else
    echo "No verification output" >> "$REPORT_FILE"
fi

exit $EXIT_CODE
