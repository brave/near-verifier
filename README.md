# near-tee-verifier

Independently verify that the backend behind [Brave Leo](https://brave.com/leo/), NEAR AI Cloud, is running the code it claims to, inside genuine Intel TDX and NVIDIA confidential-compute hardware.

You can run this yourself against the live production service. It needs no Brave or AWS credentials, only a NEAR API key. See [Verify it yourself](#verify-it-yourself-standalone-no-aws). What the tool does and does not establish is set out in [Trust assumptions](#trust-assumptions).

Licensed under [MPL-2.0](LICENSE). Security reports: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md).

## Overview

This tool performs comprehensive TEE (Trusted Execution Environment) attestation verification across the NEAR AI Cloud infrastructure. In plain terms, it confirms that:

- **Gateway**: The cloud API server is running trusted code (full SLSA provenance + reproducible build) in a secure processor and hasn't been tampered with
- **Models**: AI models are running on genuine NVIDIA GPUs with proper attestation
- **Inference**: Each model's CVM is verified end-to-end. The compose-manager actions log proves which model image is actually serving, and the NEAR-authored inference images (compose-manager, proxy) are validated to the same bar as the gateway; the compose-manager-launcher gets pinned provenance only (it is not rebuilt; NEAR is tracking reproducible builds in [nearai/compose-manager#64](https://github.com/nearai/compose-manager/issues/64))
- **TLS Certificate**: The connection to the service is encrypted and authenticated to the correct domain

Verification details:

| Component | Verification | Pass Criteria |
|-----------|--------------|---------------|
| **Gateway** | TDX attestation, pinned dstack OS measurements, report data validity, Docker Compose verification (provenance + reproducible build) | All checks must be `true` |
| **Models** | NVIDIA GPU attestation | `gpu_verified=true` for each model |
| **Inference** | Inference-proxy TDX quote + pinned OS measurements + report-data binding, compose_hash, same-CVM compose-manager quote (actions-log binding), serving-compose hash, full validation of NEAR inference images | All checks must be `true` |
| **TLS Certificate** | Domain verification, certificate validity, fingerprint matching | `certificate_verified=true`, `fingerprint_matches=true`, `domain="cloud-api.near.ai"` |

**Overall Result:** Success only if all components pass all verification checks. A check that fails is logged and fails validation. A step that cannot run at all (the NRAS call or GPU token fails, the TLS evidence chain fails validation, the live certificate cannot be fetched, the report has no `gateway_attestation`) stops the run with exit code 1 and no report. A report that carries no TLS certificate at all fails with every TLS field false.

## Trust assumptions

A verifier is only as meaningful as the things it refuses to take on faith, so here is exactly what this tool trusts and what it does not establish.

**Trusted roots.** A pass depends on these being honest; the tool cannot check them from the inside:

- **Intel**: the DCAP collateral served by the PCCS and the SGX/TDX attestation roots. A compromised Intel signing key means a forged quote verifies.
- **NVIDIA**: the Remote Attestation Service (NRAS) and the JWKS at `nras.attestation.nvidia.com` that signs its GPU verdicts.
- **Sigstore**: Fulcio and Rekor, as the authority for SLSA provenance signatures and the certificate-identity bindings in `CERT_IDENTITY_REGEXP`.
- **The dstack OS**: the firmware, kernel and initrd whose measurements are pinned in `EXPECTED_OS_MEASUREMENTS`. That OS is what enforces that `MR_CONFIG_ID` is the real compose hash; the tool trusts it to do so.
- **Google Public DNS**: the CAA check resolves records through `dns.google`, so it trusts that resolver's answers.
- **The `nearai/*` GitHub repositories** as the source of truth that reproducible builds are compared against.
- **Hugging Face** to serve the bytes of each approved weights revision in `APPROVED_MODEL_WEIGHTS`. The verifier pins the revision the serving compose loads, not a hash of the downloaded files. The model services keep weights in a persistent `huggingface_cache` volume and run with `HF_HUB_OFFLINE=1`, so files an earlier compose wrote into an approved snapshot directory would be served as that revision.
- **Two certificate trust stores.** The attested evidence chain must validate to a root in the Mozilla root program as shipped by the pinned `certifi` dependency. The *live* connection is validated separately against the operating system's trust store. A root wrongly present in either is a root this tool will accept.

**Trusted humans and operations.** These are the weakest links in practice:

- **The pins in `verifier/config.py`.** Every guarantee reduces to "the running bytes match *this specific commit*" (and, for the OS, "the CVM booted *this specific* dstack release"). That commit is correct only because a human reviewed it via `make review-pins`. A rubber-stamped pin bump silently widens what the tool will accept.
- **compose-manager, as the author of the actions log.** Which model image and proxy are serving is read from a log compose-manager writes, so a pass assumes the compose-manager code is honest. That code is reviewable: the boot compose-manager measured into the quote must come from a commit in `BOOT_COMPOSE_MANAGER_COMMITS`, and the running one from the pinned commit, both confirmed through Sigstore-verified SLSA provenance and a reproducible rebuild. Reviewing those commits for honest logging is part of approving them.
- **compose-manager-launcher, as the chooser of compose-manager.** The launcher (pinned by digest in the measured boot compose) pulls new compose-manager images, and the app_compose `pre_launch_script` restores its last choice on reboot, so the measured default compose-manager is not necessarily the one that booted. The launcher's commit is pinned and its provenance verified, but it is **not rebuilt**: NEAR builds it with wall-clock timestamps and unpinned Alpine packages, so no rebuild can match its digest. Its own policy accepts any compose-manager image signed by any `nearai/compose-manager` workflow on any ref, so until compose-manager reports itself in the actions log, that is the bound on what can run.
- **compose-manager's actions log, as the record of what runs.** compose-manager runs every deploy as `docker compose up -d --remove-orphans`, but the log omits the Compose project a deploy targets and the env vars it passes. The verifier takes a file's top-level `name` as its project (default `work`). A deploy into another project, or env that changes a model service's behaviour, is not seen. The log also does not record when a one-shot service exits, so the replay keeps it as running.
- **Write access to the `pre-verified/`, `signing-keys/`, `serving-compose/` and `serving-log/` S3 prefixes.** The verifier treats a pre-verified entry as proof an image passed full provenance and reproducibility. Entries are integrity-checked and digest-bound on load, so a tampered entry cannot turn a failure into a pass or replay one image's verdict onto another. That is defence in depth, not access control. If an untrusted party can write those prefixes, they can forge approvals.

**What a pass does *not* establish:**

- **That the audited source is benign.** Reproducibility proves the deployed bytes were built from the pinned commit. It says nothing about whether that commit contains a backdoor. Human review at pin-bump time is the only thing standing there; the `[s]can` privacy review assists it, but that is an AI review of a diff rather than a proof, and it is a maintainer-side convenience that does not run as part of verification at all.
- **That the model runtime image is verified to the same bar.** Two different images are easy to confuse here. `vllm-proxy-rs` is NEAR-authored and *is* fully verified (SLSA provenance plus reproducible rebuild), apart from the exact images listed in `ACCEPTED_EXTRA_PROXY_IMAGES` (see `near_images_verified`). The **model runtime** itself (vllm, sglang, …) is third-party: it gets no provenance check and is not rebuilt. What the tool establishes is *which* runtime image is serving, via the hardware-attested compose-manager actions log, not that the image was built from audited source.
- **Anything after the attested boundary.** The tool verifies the CVM serving a request, not what a correct CVM chooses to do with your prompt.
- **The whole compose file.** Only the NEAR images in `CERT_REPOSITORIES` / `INFERENCE_REPOSITORIES` are verified. Any other image in the compose (third-party sidecars), in the serving composes and in the boot compose, is listed in the report as `unverified_images` but not checked. The boot app_compose's `pre_launch_script`, volume mounts and privileged settings are not inspected either, beyond the image rule below: a `pre_launch_script` is treated as able to set any variable. Running serving services are held to the socket rule under `serving_yaml_verified`.
- **Which GPU served you.** NVIDIA's signed verdict proves genuine GPUs produced fresh evidence for our nonce, but nothing in the TDX quote commits to that evidence, so a gateway could relay the nonce to genuine GPUs elsewhere. Closing this needs NEAR to bind the GPU evidence into the CVM's `report_data`.
- **Image authenticity via separate signatures.** NEAR publishes SLSA provenance attestations rather than standalone cosign signatures, so provenance *is* the authenticity mechanism here, and the report says so: the `image_provenance_verified` field means "every image's SLSA provenance verified".
- **Continuous assurance.** A run attests to the deployment *at that moment*, bound to a fresh nonce. It says nothing about the next request.

## Privacy

The security model above covers what the tool believes; this section covers what it *sends*. No chat or inference traffic flows through this tool. It verifies attestation evidence and does not talk to the models. What follows is the complete set of network parties a run contacts.

### What a run sends

The only operator inputs that leave the machine are:

- **The model name** (`MODEL_NAME` / `--model`), sent as a query parameter on each attestation-report request. It selects which deployment's evidence is returned.
- **The NEAR API key**, sent as a Bearer header on those same requests and to no one else. It is never written to a log: it goes into the request header and nowhere else.
- **A random nonce**, sent as a query parameter so the returned quotes can be bound to this run (anti-replay). A fresh nonce is generated per run for the main pass; on a passing run with S3 persistence enabled, the report is fetched again once per additional signing scheme, each with its own fresh nonce, to record that scheme's signing key.

That is all. No prompt, message or conversation content exists anywhere in the tool's inputs, so none can be transmitted.

### Parties contacted

| Party | Why | What's in the request |
|---|---|---|
| The configured gateway (prod `cloud-api.near.ai`, staging `cloud-stg-api.near.ai`, or a `BASE_URL` override, https only) | Fetch the attestation report, including TLS evidence | Model name, nonce, signing scheme; the API key as a Bearer header |
| Intel PCS/PCCS (`api.trustedservices.intel.com`, via dcap-qvl) | Fetch the DCAP collateral needed to verify a TDX quote | The TDX quote itself |
| NVIDIA NRAS (`nras.attestation.nvidia.com`) | Attest the GPU evidence, and serve the JWKS its verdict is checked against | The server-supplied GPU attestation payload |
| Sigstore (Rekor transparency log and Fulcio certificate chain, via cosign) | Verify each image's SLSA provenance signature | Image references and digests; the signing-identity parameters are applied locally to what comes back |
| `raw.githubusercontent.com` | Fetch the serving compose files at the attested commit | Repository, commit and file path |
| `github.com` | Clone the audited source for the reproducible rebuilds | `git clone` of the source repository recorded in each image's verified provenance, restricted to the audited repos |
| Container registries | cosign fetches each image's provenance attestations; also see the rebuild caveat below | Image references and digests |
| `dns.google` | The CAA lookup | The domain name being queried |
| Amazon S3 (only when `NEAR_BUCKET_NAME` is set) | Read the pre-verified image cache; and, when persistence is on, write the report and approval markers | Image digests for cache reads; the report and marker contents (attestation metadata) for writes |

Every upstream connection runs with TLS certificate verification enabled; it is never disabled. Which trust store a given connection validates against is covered by the [Trust assumptions](#trust-assumptions) note on the two trust stores.

**The rebuild caveat, privacy side.** The reproducible rebuild executes each image's own build script with Docker access. That is host-equivalent, third-party code. It runs in an allowlisted environment that strips the API key, AWS credentials and bucket names. The verifier's code contacts only the hosts in the table above, but a build script can pull base images and other content from whatever registries its own `Dockerfile` names, and hosts those reach; and the rebuild's `git` signature check may contact keyservers if your local GPG configuration enables auto-key-retrieval. This is the same caveat as the [Quick Start](#verify-it-yourself-standalone-no-aws) warning about running the tool somewhere disposable.

### What the tool never touches

- **No chat or inference calls.** The tool never sends a prompt or receives a completion. Nothing in it speaks the inference API.
- **No prompt or conversation content.** There is no such input to leak: no user content exists anywhere in the tool's data flow.
- **Your API key and model name** are the only operator inputs transmitted, and the API key is never logged.
- **huggingface.co is never contacted by the verifier.** Model weights are referenced by Hugging Face path in the compose files it inspects; Hugging Face URLs appear in output only as links for a human to open. (The model services themselves fetch weights at deploy time, on NEAR's side of the boundary.)

### Opt-in persistence

Writing anything to S3 is opt-in: it happens only when `NEAR_BUCKET_NAME` is set and `--no-persist` is not, and a `--skip-reproducibility` run writes nothing. When enabled, what is written is attestation metadata only: image digests and their verification verdicts, the signing public keys recorded from verified quotes, model ids, serving compose files and weight revisions, and timestamps. There is no user content in the tool to write. See [Outputs: the S3 access gate](#outputs-the-s3-access-gate) for what each object contains and who reads them.

### Maintainer tooling

Not part of a verification run. `make review-pins` (`scripts/review_pins.py`) uses your authenticated `gh` and `git` CLIs to compare pins against live attestations and open release PRs. If you supply the CodeBuild project and aws-vault profile, it can also start Brave's AWS CodeBuild verification for the affected environments once a release PR merges. Its optional `[s]can` step pipes a third-party code diff to the Claude CLI for the AI privacy review; that is opt-in and the prompt file is not distributed with the repo. CI in this repository runs only its own tests and static checks (lint, types, bandit, vulture); nothing is sent anywhere by CI beyond fetching the repo and dependencies.

## Quick Start

### Verify it yourself (standalone, no AWS)

You need Python 3.11+, [Docker Compose](https://docs.docker.com/compose/install/) v5.1.4 (the `docker compose` plugin, or a standalone binary named in `COMPOSE_BIN`; the version must match the one compose-manager runs), [Poetry](https://python-poetry.org/docs/#installation), [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3 or later (every run checks SLSA provenance with it; older releases do not resolve OCI 1.1 referrers), `git` and Docker (for the reproducibility rebuilds), and a NEAR API key:

```bash
make install                      # or: poetry install
export NEAR_API_KEY=<your-key>
MODEL_NAME="z-ai/glm-5.3-flash" poetry run verify-near-tee
```

`verify-near-tee` reads its settings from the environment only; it does not load `.env.local` (`make test-local` does).

> **Run it somewhere disposable.** The reproducibility step runs each image's own build script with Docker access, which is host-equivalent. The script gets an allowlisted environment (no API keys or AWS credentials), but it is still third-party code.

`MODEL_NAME` is the marketplace model id (see `/v1/models` on the gateway) and is the only model knob: it addresses the gateway attestation request, selects the per-model `vllm-proxy-rs` pin, and is the id the attested `model_name` must match. `--model` defaults to it; override both together or not at all.

Exit code is **0** only if every check passed, **1** otherwise (**2** for an invalid command line). That includes the case where every check passed but writing the report to S3 failed, so a green run can never be recorded as green without a persisted report to back it. With no `NEAR_BUCKET_NAME` set, **nothing is written to S3**. You just get the result and exit code. No AWS credentials or setup required.

A failed run usually means NEAR has deployed a build that Brave has not reviewed yet, so the pins in `verifier/config.py` no longer match. It is not by itself a sign that anything is wrong; see [SECURITY.md](SECURITY.md).

No Docker (or want a fast check)? Add `--skip-reproducibility` for a provenance-only run. See the weaker-guarantee note below. cosign is still required.

#### Options

| Flag / env | Effect |
|---|---|
| `NEAR_API_KEY` *(env, required)* | API key for the attestation endpoint. `NEAR_API_KEY_PROD` / `NEAR_API_KEY_STAGING` take precedence for their environment; `API_KEY` is a last fallback |
| `MODEL_NAME` *(env)* | Marketplace model id to verify, e.g. `z-ai/glm-5.3-flash` (see `/v1/models`). Selects the gateway report, the inference chain, and the per-model `vllm-proxy-rs` pin |
| `--model <id>` | Same thing on the command line; defaults to `MODEL_NAME`. The run aborts if the two disagree, because the proxy pin is resolved from `MODEL_NAME` |
| `NEAR_ENV` *(env)* | Deployment to verify: `prod` (default) or `staging`. Selects the gateway URL and the environment's gateway commit pins. Inference CVMs are shared across both. |
| `BASE_URL` *(env)* | Gateway URL override (defaults to the `NEAR_ENV` gateway: prod `https://cloud-api.near.ai`, staging `https://cloud-stg-api.near.ai`). Must be `https://` |
| `--output FILE` | Write the JSON report to `FILE` |
| `--json` | Print the JSON report to stdout (logs and the pin-update guide go to stderr) |
| `--quiet` / `--verbose` | Less / more logging |
| `--skip-reproducibility` | Provenance-only; skip the Docker rebuild. **Weaker guarantee**: confirms each image's signed SLSA provenance but not that the running bytes are reproducible from audited source. Use only without Docker or for a quick check. Disables S3 persistence. |
| `NEAR_BUCKET_NAME` *(env)* | Enable S3 persistence of the report + per-digest approval markers (off when unset) |
| `--no-persist` | Force-skip S3 writes even if `NEAR_BUCKET_NAME` is set (the pre-verified cache is still read from it) |
| `PRE_VERIFY_DISABLED` *(env)* | Any non-empty value (even `0`) re-verifies every image instead of reusing the per-digest cache |
| `COMPOSE_BIN` *(env)* | Path to a standalone `docker-compose` binary to use instead of the `docker compose` plugin. It must be version `COMPOSE_VERSION` (5.1.4) |
| `BUILD_CACHE_DIR` *(env)* | Keep source clones here between runs, keyed by image digest. A cached clone is used only if its HEAD is the provenance commit, and the image is always rebuilt. Use a directory only you can write |
| `BUILD_WRAPPER_SCRIPT` *(env)* | Replace every image's own build script with this one (e.g. `scripts/build-wrapper.sh`, a buildx build modelled on cloud-api's). Debugging aid: a match then proves this script reproduces the digest, not the project's own build |

### Run via Make / AWS CodeBuild

```bash
make test-local         # local verification run (reads .env.local)
make test-local-again   # same, reusing the previous run's setup
make run                # CodeBuild simulation locally (Docker)
```

`test-local.sh` takes `-v/--verbose` and `-s/--skip-setup`. `scripts/run-codebuild-local.sh` takes `-v`, `-i <image>`, `-o <output dir>`, `-r <aws region>`, `-b <buildspec>` and `-e <env file>`; run it with `-h` for details.

S3 persistence (the report + approval markers) is enabled only when `NEAR_BUCKET_NAME` is set, which the CodeBuild job provides.

### Pre-Verification (Release Speed-up)

Image verification (cosign provenance checks + reproducibility rebuilds) can take 30 minutes to 2 hours per image. To keep that cost off the critical path, the verifier **reuses a previously-validated result for an unchanged image digest by default**. Each fully-validated image is recorded in S3 under `pre-verified/<digest>.json`, and a later run skips cosign and the reproducibility rebuild for any digest already there. A normal release populates the cache as it goes, so follow-up releases only do the full work for images whose digest actually changed.

A cache **miss**, an unreadable bucket, or an entry that fails the integrity check all fall through to full verification, so the reuse can only ever speed things up. It never weakens the gate. Set `PRE_VERIFY_DISABLED=1` to force full re-verification of every image (e.g. a clean-room audit run).

**Optional: warm the cache before a release** (so the first release after a new build is already fast). This covers the gateway images (`CERT_REPOSITORIES`) only. Inference images and any third-party image make it exit non-zero. `scripts/pre-verify.sh` wraps `python -m verifier.pre_verify --compose FILE` / `--image REF...`:

```bash
# From a compose file
NEAR_BUCKET_NAME=your-bucket \
COMPOSE_FILE=/path/to/docker-compose.yml \
bash scripts/pre-verify.sh

# Or with explicit image references
NEAR_BUCKET_NAME=your-bucket \
IMAGE_REFS="nearaidev/cloud-api@sha256:abc... nearaidev/cvm-ingress@sha256:def..." \
bash scripts/pre-verify.sh
```

> **Security: the cache is part of the access gate.** The verifier treats a pre-verified result as proof an image passed full provenance + reproducibility. Each cache entry is validated on load. It must be well-formed and bound to the exact requested digest, and a claimed reproducible build must reference that digest. Any entry that fails these checks is ignored in favour of full verification, so a tampered entry can never turn a failure into a pass or replay one image's verdict onto another. That defence-in-depth does **not** replace access control. The `pre-verified/` prefix **must be writable only by the verifier and pre-verify principals** (in Brave's deployment, internal CI roles) and read-only to everything else. If an untrusted party can write that prefix, they can forge approvals.

## Development

### Setup

```bash
make install
poetry run pre-commit install
```

Pre-commit hooks will automatically run on every commit to:
- Format code with `ruff`
- Lint code with `ruff`
- Type check with `mypy`
- Check for security vulnerabilities with `bandit`

If hooks modify files during commit, stage the changes and commit again.

## AWS CodeBuild (Brave maintainers only)

Brave runs the verifier on a schedule in AWS CodeBuild and uploads each report to S3. That path needs Brave AWS credentials, so it cannot be run outside Brave. The CodeBuild project and the aws-vault profile allowed to start it are supplied by the caller rather than stored here:

```bash
make codebuild-prod    CODEBUILD_PROJECT=<project> AWS_VAULT_PROFILE=<profile>
make codebuild-staging CODEBUILD_PROJECT=<project> AWS_VAULT_PROFILE=<profile>
```

**None of this is required to verify Brave's claims yourself.** The verifier runs standalone against the live production service with no AWS access. See [Verify it yourself](#verify-it-yourself-standalone-no-aws).

## Configuration

Copy [`.env.example`](.env.example) to `.env.local` and fill it in. `.env.local` is gitignored, and is read by `make test-local`, `make run` and `make review-pins` (not by `verify-near-tee` itself; export the variables for that):

```bash
cp .env.example .env.local
```

Only `NEAR_API_KEY_PROD` is required for a standard production run; everything else has a working default. `.env.example` documents each variable, including the optional S3 and cache settings. The release tool (`make review-pins`) checks both deployments, which use different keys, so set `NEAR_API_KEY_STAGING` too if you intend to verify staging.

### Production vs. staging

Set `NEAR_ENV=staging` to verify NEAR's staging gateway (`https://cloud-stg-api.near.ai`) instead of production. The gateway is a separate deployment in each environment, built from different commits, so each has its own audited gateway pins in `config.py` (`_GATEWAY_EXPECTED_COMMITS`). The inference CVMs (compose-manager, vllm-proxy-rs, and the per-model completions endpoints) are shared across both environments, so those pins carry over.

Staging's `cloud-api` churns fast, often more than once a day, so its pin goes stale quickly and a staging run is expected to report a mismatch more often than prod. Re-extract it right before a run with `make review-pins ENV=staging`.

## Keeping pins in sync with `make review-pins`

`scripts/review_pins.py` is the maintainer workflow for catching up to what NEAR actually deploys. It compares `verifier/config.py` against NEAR's **live** prod and staging attestations, and for each image that differs walks you from review to a merged, verified release:

```bash
make review-pins                 # both prod and staging (default)
make review-pins ENV=prod        # prod only
make review-pins ENV=staging     # staging only
```

Requires the per-environment keys in `.env.local` (see [Configuration](#configuration)). Staging's attestation needs a bearer token.

What it does:

1. Fetches each chosen environment's attestation and reads the deployed commit of every pinned image (verified from the image's signed SLSA provenance), then prints how it differs from `config.py`, with the release date/time of both the pinned and the deployed commit.
2. For each changed service you get a menu:
   - **`[v]iew`**: open the old→new code diff in your editor (neovim Diffview by default; override with `PIN_REVIEW_DIFF_CMD`).
   - **`[c]ompare`**: open the GitHub compare page.
   - **`[s]can`**: run an AI **privacy review** of the diff (see below).
   - **`[a]pprove`**: accept the bump.
3. Approved bumps are written to `config.py`, committed on a release branch cut from `master`, and opened as a PR. An inference CVM's **boot** compose-manager is listed as `nearaidev/compose-manager (boot)` when its commit is not yet in `BOOT_COMPOSE_MANAGER_COMMITS`; it is diffed from the running compose-manager pin, and approving it adds the commit to that set rather than replacing a pin.
4. The tool then waits for the PR to merge (it can merge it for you) and, from your terminal, starts the CodeBuild verification for the affected environment(s). A change to a **shared inference** image re-verifies every chosen environment; a gateway change re-verifies only its own. This step needs `CODEBUILD_PROJECT` and `AWS_VAULT_PROFILE` (or `PIN_REVIEW_CODEBUILD_CMD`); without them nothing is started.

Model weights are reviewed the same way. Each run reads the weights the serving compose loads, and any not in `APPROVED_MODEL_WEIGHTS` for that model shows up as a `model weights [<model>]` change. `[c]ompare` opens the Hugging Face snapshot (weights have no code diff, so `[v]iew` and `[s]can` do not apply). Approving it replaces the approved revision of the same Hugging Face repo, or adds the repo if it is new. Weights that are not a pinned snapshot are reported as unreadable and can never be approved. A failed verification run lists the same weights in its pin-update guide.

`MODEL_NAME`, exported in the shell, narrows the review to specific models (comma-separated). It is not read from `.env.local`. By default every model pinned in `_PROXY_EXPECTED_COMMITS` is checked. The workflow needs the GitHub CLI (`gh`), authenticated.

### AI privacy scan (`[s]can`)

`[s]can` pipes the service's diff, along with a privacy-review prompt, to the Claude CLI (`claude`). It checks one thing: that the change doesn't weaken the user-prompt privacy invariant of NEAR's OHTTP inference path (no new plaintext log/metric/cache sink, no plaintext egress off the local model backend, telemetry not widened to carry content). The prompt asks the CLI for a verdict plus findings. Override the CLI with `PIN_REVIEW_CLAUDE_CMD`.

**The prompt itself is not distributed with this repo.** Without it `[s]can` shows as `[s]can(n/a)` and declines, which affects only this maintainer convenience. No verification check depends on it. To enable it, place a prompt file at `scripts/privacy_review_prompt.md` (gitignored) or point `PIN_REVIEW_PROMPT_FILE` at one.

### API keys in CodeBuild

The verifier picks its bearer token by environment. `config.py` reads `NEAR_API_KEY_PROD` when `NEAR_ENV=prod` and `NEAR_API_KEY_STAGING` when `NEAR_ENV=staging`. The CodeBuild project provides both as `SECRETS_MANAGER` environment variables, so a staging build only needs the `NEAR_ENV=staging` override. No key is passed on the command line. Both environments require a key.

### Environment overrides

| Env var | Effect |
|---|---|
| `PIN_REVIEW_DIFF_CMD` | Editor diff command; `{have}`/`{need}` are the commits (default: `nvim -c "DiffviewOpen {have}..{need}"`) |
| `PIN_REVIEW_CLAUDE_CMD` | Claude CLI used by `[s]can` (default: `claude`) |
| `PIN_REVIEW_PROMPT_FILE` | Privacy-review prompt for `[s]can` (default: `scripts/privacy_review_prompt.md`, not shipped) |
| `PIN_REVIEW_BASE_BRANCH` | Branch the PR targets (default: `master`) |
| `PIN_REVIEW_CODEBUILD_CMD` | Override the CodeBuild command; `{env}` is substituted |
| `CODEBUILD_PROJECT` / `AWS_VAULT_PROFILE` | CodeBuild project to start on merge and the aws-vault profile allowed to start it (Brave-internal; also read from `.env.local`) |

## Validations

Every check below must pass. Each is a link in a chain from the Intel/NVIDIA hardware roots of trust up to the exact source code and the network identity a client connects to. A failure anywhere fails the whole run, and the verification report and the `pre-verified/` image-approval markers are **not written to S3**.

That includes the `signing-keys/` markers. A key held by a CVM whose OS, compose or images did not verify is a key held by unaudited code, so a failed run records no keys either. A key for the second signature scheme comes from a fresh request that may reach another replica, so it is recorded only if that replica attests the same verified state: the same boot compose, and a same-CVM, nonce-bound compose-manager actions log naming the same serving compose and running compose-manager the main pass verified.

### Gateway CVM

The cloud-api gateway (which also hosts cvm-ingress in the same CVM).

- **`tdx_verified`**: The Intel TDX quote is verified against Intel collateral via `dcap-qvl`. Acceptable TCB statuses are `UpToDate` and `SWHardeningNeeded` (current TCB, with advisory software mitigations required). **`OutOfDate` is rejected**: it means the platform microcode, TDX module or SEAM is behind the security baseline, so published CVEs are unpatched on that host. This proves the workload runs on genuine, measured Intel TDX hardware with a current TCB.

  The one exception is `ACCEPTED_OUTOFDATE_ADVISORIES` in `verifier/config.py`. An `OutOfDate` quote passes only when every advisory it reports is in that list. Any other advisory, or an `OutOfDate` quote with none listed, still fails. Remove the entries once the host firmware is updated.
- **`os_measurements_valid`**: The quote's `MRTD` (firmware), `RTMR0` (boot configuration), `RTMR1` (kernel) and `RTMR2` (cmdline + initrd) are one of the tuples pinned in `EXPECTED_OS_MEASUREMENTS`. `MR_CONFIG_ID` is chosen by the host when the TD is created, and only the genuine dstack OS makes it equal the compose hash. Without this pin, anyone with a production TDX host could boot their own TD with a legitimate `MR_CONFIG_ID` and pass every other check. An empty pin set fails closed, and the failure names the observed tuple to audit. The staging tuple is pinned from DCAP-verified quotes only; the prod tuples were reproduced with `dstack-mr`. Cross-check new values against the measurements dstack's reproducible OS build produces for that release before pinning them.
- **`mrconfig_valid`**: The hardware-measured `MR_CONFIG_ID` equals `0x01 || SHA256(app_compose)` followed by 15 zero bytes, compared in full. This binds the compose configuration served by the API to the hardware quote, so a compromised API cannot swap in a different compose while reusing a legitimate quote.
- **`report_data_valid`**: The quote's `report_data` binds the **TLS-certificate fingerprint** **and** the caller's random nonce. The signing address alone is *not* accepted here: it is drawn from the same attestation blob and no response signature is ever checked against it, so only the certificate binding anchors the quote to the channel the client actually talks to. This proves the attested CVM terminates this connection and that the quote is fresh for this request (anti-replay).
- **`compose_verified`**: For **every** required image pinned in the compose file, the SLSA provenance is verified with cosign (keyless GitHub OIDC issuer, audited source repo, an allow-listed **builder identity**, the exact pinned commit in `CERT_EXPECTED_COMMITS`, and Rekor transparency-log inclusion) **and** the image is **reproducibly rebuilt** from that source commit and its digest is confirmed to match. Provenance alone is not enough. The running bytes must be reproducible from audited source.

  Several things fail closed rather than passing quietly: an image with **no pin configured** is an error, not a skip (the message names the deployed commit to audit); a rebuild whose digest cannot be read is a failure, so two unreadable digests can never compare equal; and if **no image was checked at all** this fails rather than vacuously passing. Rebuilds also supply the per-image build arguments production CI uses (`CERT_BUILD_ENV`), so the comparison is against the deployed variant rather than a different build of the same source. The cosign certificate-identity patterns are anchored at both ends, so a signing identity that merely *contains* the expected workflow path cannot satisfy them.

  The compose is parsed as YAML and only each service's own `image` key counts, so an `image:` string in a comment, label or environment value cannot stand in for the real one. Docker Hub spellings (`docker.io/…`, `index.docker.io/…`) and quoting are normalised, so they cannot hide a required image either. A required image not referenced as exactly `name@sha256:<digest>` fails, since it would run unverified next to a pinned decoy. So does one set from a `${VAR:-default}` whose `VAR` is in the app_compose `allowed_envs`, because the operator can override it at deploy time, and one set from *any* variable when the app_compose has a non-empty `pre_launch_script`, which runs before the compose and can export anything. The one exception is the inference boot compose-manager, whose variable NEAR's `pre_launch_script` sets to the launcher's last choice; the launcher is verified instead (see the trust assumptions). Every other image is reported in `unverified_images`, including a service with no `image` at all (e.g. one built locally).

  Two documented exceptions: `--skip-reproducibility` downgrades this to provenance-only, and images listed in `CERT_SKIP_REPRODUCIBILITY` are exempt from the rebuild. That set holds only `compose-manager-launcher` (see the trust assumptions).

### Models (GPU)

- **`gpu_verified`**: The model's `nvidia_payload` is submitted to NVIDIA's Remote Attestation Service (NRAS). The returned JWT is signature-verified against NVIDIA's JWKS (asymmetric algorithms only, with `none`/HMAC rejected), must carry an expiry that has not passed, and the overall attestation result must be true. This proves the model runs on genuine, attested NVIDIA GPUs.

  Freshness is taken from the nonce claim **inside NVIDIA's signed token**, not from the unsigned evidence payload, which can be swapped onto replayed but otherwise genuine evidence. If the signed token carries no recognisable nonce claim, freshness is unprovable and the check fails closed. A missing overall result claim likewise counts as a failure, not a pass.

### Inference CVMs (per model)

The gateway `compose_hash` does **not** reflect runtime model swaps: `compose-manager` (baked into the inference boot compose) pulls model compose files from the `cvm-compose-files` repo at runtime. Verifying which model image is actually serving therefore requires the full chain below. It is verified from the per-model attestation the gateway report already carries in `model_attestations[]`: cloud-api propagates the request nonce into both the inference-proxy and compose-manager quotes, so no per-model endpoint is involved.

- **`model_name_matches`**: The attested `model_name` is the model that was requested. cloud-api selects the attestation from the `model` query parameter and can alias a retired id onto whatever model replaced it, which would otherwise verify cleanly while attesting the wrong deployment. An attestation that omits the model id does not match either, because it cannot say what it is for.

- **`tdx_verified`**, **`os_measurements_valid`**, **`mrconfig_valid`**: As for the gateway, applied to the inference-proxy CVM's quote.
- **`compose_hash_valid`**: `SHA256(app_compose)` equals the report's declared `compose_hash`.
- **`proxy_report_data_valid`**: The inference-proxy quote's `report_data` binds the signing address (or the TLS certificate fingerprint) and the request nonce. The gateway is held to a stricter bar: it must bind the TLS fingerprint specifically, because it terminates the client's connection; the inference proxy does not.
- **`compose_manager_tdx_verified`**: The embedded compose-manager TDX quote verifies.
- **`actions_hash_bound` / `nonce_bound`**: The compose-manager quote's `report_data` binds the actions-log hash (bytes 0 to 32) and the request nonce (bytes 32 to 64), proving the actions log came from the attested compose-manager and is fresh. Both are reported individually and are folded into the gated `report_data_valid`, which requires every report-data and freshness binding in the chain to hold.
- **`same_cvm`**: The inference-proxy and compose-manager quotes share identical TDX measurements (`mr_td`, `mr_config_id`, and RTMR0 to RTMR3). MRTD, MRCONFIG and RTMR0-2 are the same on every replica of a deployment; RTMR3 carries the instance's boot events, so it tells replicas apart. That rules out pairing one replica's proxy quote with another replica's compose-manager quote. A runtime event extended into RTMR3 between the two quotes would fail the check closed. A quote with no decoded measurements cannot satisfy this vacuously.
- **`serving_yaml_verified`**: The actions log replays to the services now running. Every compose file is read through `docker compose config --no-interpolate` at the version compose-manager runs (`COMPOSE_VERSION`), so `include`, `extends`, merge keys, implicit dependencies and path resolution are applied exactly as `up` applies them; a file Compose cannot read leaves the state unknown and fails the check. Each log entry must name a full 40-hex commit and a plain file path. Each `compose_up` starts its listed services and everything they depend on (all of the file's when none are listed) and, as `--remove-orphans` does, evicts the project's services the file does not define. Each `compose_down` stops its listed services (all of the file's when none are listed). Every file the log names is fetched from `cvm-compose-files` at the logged commit, and each `compose_up` file's `SHA256` must match its `file_sha256`. Any file that cannot be fetched or fails its hash fails the check. The running services' definitions, taken from the file each came from, are what the weights and image checks read. No running service other than the `vllm-proxy-rs` proxy may bind-mount the dstack socket, and none may bind-mount the Docker socket, or `/`, `/var`, `/var/run` or `/run`, or a host path from `${VAR}`, after Compose resolves relative and `~` paths and the path is normalised: either socket would let it act outside the actions log. A service outside a recognised inference server may not reach the GPUs either (only the `vllm-proxy-rs` proxy and the DCGM exporter may), counting a runtime, device reservation, `privileged`, `env_file` or passed-through `NVIDIA_VISIBLE_DEVICES`: the same rule that gates serving-compose approval, applied here when the verdict is issued, so an approved-weights model cannot be paired with an arbitrary GPU-attached sidecar and still pass. No running service may use a `post_start` or `pre_stop` hook, or start a server from its healthcheck. Services from a reviewed file in `APPROVED_MAINTENANCE_COMPOSES` are exempt. The files are reported as `serving_composes`.
- **`model_weights_approved`**: Every `--model-path` or `--model` of a running service, and every `--chat-template`, `--tokenizer-path`, `--tokenizer`, `--speculative-draft-model-path`, `--speculative-model`, `--speculative-config`, `--lora-paths` or `--lora-modules`, is a Hugging Face snapshot or a file inside one (`/root/.cache/huggingface/hub/models--<org>--<name>/snapshots/<revision>`, the whole path) listed for the requested model in `APPROVED_MODEL_WEIGHTS`. Each service's `command` and `entrypoint`, as Compose resolves them, are split like compose splits them, so a comment or label does not count. Flags are read the way argparse reads them: `_` and `-` are interchangeable, an abbreviated flag fails, a dotted key such as `--speculative-config.model` counts as its flag, and the positional model of `vllm serve <model>` counts as a model path. `--load-format dummy`, a `--config` file on a server, and any `${VAR}` in a server's arguments fail, since the check cannot see what they load. A service that runs an inference server (`sglang serve`, `vllm serve`, `--served-model-name` or the `vllm/vllm-openai` image) must load approved weights. An unlisted repo or revision, a path that is not exactly a pinned snapshot, a server with no model path, or a YAML with no model path at all fails. A server image that loads weights without any of those markers is not detected, because the inference server images are not verified. The weights found are reported as `serving_weights`. Between runs, Brave's gateway relay ([brave/ai-gateway](https://github.com/brave/ai-gateway), `aichat/serve/services/near.py`), which reads these markers to admit traffic, refuses a deploy of any compose file the verifier has not approved (see the `serving-compose/` and `serving-log/` markers below).
- **`near_images_verified`**: The NEAR-authored inference images (`compose-manager`, the `vllm-proxy-rs` proxy) pass the same full provenance + reproducible-rebuild validation as the gateway images. The `compose-manager-launcher` from the boot compose passes pinned provenance only (it is not rebuilt; see the trust assumptions). Exact proxy images listed in `ACCEPTED_EXTRA_PROXY_IMAGES` for the model are left out of this check, provided a pinned proxy is also running and passes; the report still lists them, and the pin-drift guide does not suggest pinning them. The third-party model runtime image (e.g. vllm) is not rebuilt and gets no provenance check; what is established is *which* runtime image is serving, via the actions log.

  Because compose-manager self-updates, the running compose-manager image is taken from the hardware-bound actions log rather than assumed, and it must be `nearaidev/compose-manager` pinned by digest. The boot compose must run exactly one compose-manager. That log is only as honest as the compose-manager that wrote it, and the chain of self-updates starts at the **boot** image measured into the quote. So the boot image gets the same full validation (provenance + reproducible rebuild) as the other NEAR images, except that its commit is checked against `BOOT_COMPOSE_MANAGER_COMMITS`: a set rather than one pin, since boot images vary per replica, but every entry is a commit a human reviewed. A boot image that is also the running one is not rebuilt twice. That anchor is reported as `boot_compose_manager_verified` and folded into `near_images_verified`; it fails if the boot image comes from an operator-overridable variable, and an unreviewed commit fails with a message naming it. `make review-pins` offers an unreviewed boot commit for review as a diff from the running pin, and approving it adds it to the set. If the log has no `compose_manager_started` entry, the boot image is the running one: it is held to the running pin instead, and a `pre_launch_script` then fails it.
- **`gpu_verified`**: NVIDIA NRAS check, as above. **Required**: an attestation that omits `nvidia_payload` leaves this unset, which fails the component, so the server cannot opt out of GPU verification by withholding evidence.

Actions-log integrity does **not** rest on the server-supplied `actions_hash` field, because an attacker could set that equal to the genuine `report_data` while shipping a forged `actions` list. The verifier recomputes `SHA256` over the canonical serialization of the emitted `actions` (alphabetical keys, compact, UTF-8) and requires it to equal the hardware-signed `report_data[0:32]`. Only the canonical form is accepted. The declared `actions_hash` field is read only to make failure logs readable, never for the decision.

### TLS Certificate

This ties the attested service to the network endpoint a client actually connects to.

- **`domain`** is the host of `BASE_URL`, reported for the record. It is not an independent check: the hostname is enforced by the live TLS handshake (OS trust store with SNI) plus the fingerprint match below.
- **`certificate_verified`** runs RFC 5280 path validation (`cryptography`'s `x509.verification`) from the evidence leaf to a root in the Mozilla root program shipped in `certifi`. That checks every signature and validity period, the CA and key-usage constraints on each issuer, and the leaf's name for the domain. A root is trusted by its key, not by its name, which whoever mints a certificate chooses freely.
- **`fingerprint_matches`** confirms the live served certificate matches the evidence certificate, and is reported false whenever `attestation_fingerprint_matches` is false. The live certificate is fetched under full OS trust-store validation with SNI; verification is never disabled.
- **`attestation_fingerprint_matches`** confirms the SPKI hash bound *inside the TDX quote* matches the evidence certificate. This is the check that ties the quote to this TLS channel. A report that omits the fingerprint **fails** rather than skipping the check, since otherwise the gateway under audit could opt out of it.
- **`dns_caa_verified`** confirms every CAA `issue` and `issuewild` record for the domain names Let's Encrypt (the CA NEAR uses) or forbids issuance (`;`), and that at least one `issue` record names Let's Encrypt. Other tags such as `iodef` grant nothing and are ignored. No issuance records, which would let any CA issue, fails. The issuer is compared exactly after stripping quoting and parameters, so a lookalike such as `letsencrypt.org.attacker.example` cannot smuggle through a substring test.

### Signing keys

On a run where **every** check passed, the signing key of each verified quote is recorded, but **only after** confirming it corresponds to the address that quote binds. For the gateway that address is `gateway_attestation.signing_address`, the one the quote check reads. Keys under the other signature scheme are fetched in a second request, and are recorded only if that quote verifies, binds its key (for the gateway, through the TLS certificate), has a pinned OS and carries the same `MR_CONFIG_ID` as the CVM the main pass verified. Two schemes are handled: for `ecdsa` the address is derived (secp256k1 → keccak-256 → last 20 bytes) and must equal the bound address; for `ed25519` the 32-byte public key *is* the identity and must match it directly. Any other `signing_algo`, or none, is refused outright rather than recorded unverified. A key that does not correspond to the bound address is never recorded, so the verified quote can never be attributed to the wrong key.

### Outputs: the S3 access gate

S3 persistence is **opt-in**. It runs only when `NEAR_BUCKET_NAME` is set (and not `--no-persist`). Standalone runs without a bucket just report the result and exit code. When enabled, the S3 objects are an **access gate**, not a log: a client checks an object's existence with `HeadObject`, and its presence is the verifier's stamp of approval. The object's name *is* the data.

> **Every object is written only after the whole run passes, and only on a run that required reproducible builds.** The exception is the `serving-compose/` and `serving-log/` markers, which are written whenever their own chain verifies: the attested model name, the inference CVM's TDX quote, OS measurements, mrconfig and compose hash, `report_data_valid` (which includes the proxy's report-data binding and a same-CVM compose-manager quote), compose-manager itself fully verified (`compose_manager_verified`), the log replaying cleanly, and approved weights in every running server. The `serving-log/` marker additionally requires every compose file it names to have been approved. The proxy's image verdict and the gateway are not part of that chain, so a failure there does not hold them back. A `--skip-reproducibility` run writes nothing to S3. Markers are rewritten on every passing run. Brave's bucket expires objects after 120 days, so a marker lasts as long as runs keep approving what it names.

- **Per-image-digest markers** (`pre-verified/<digest>.json`) are written for each fully-validated image digest, so a marker's presence means that exact image was provenance-checked and reproducibly rebuilt. Failed results and provenance-only (`--skip-reproducibility`) results are refused outright; the only exemption is a registry listed in `CERT_SKIP_REPRODUCIBILITY` (`compose-manager-launcher` only).
- **Signing-key markers** (`signing-keys/<key>.json`) are written for each signing key recorded as described above.
- **Serving-compose markers** (`serving-compose/<model>/<file_sha256>.json`) are written for each compose file a verified CVM runs whose every model path, chat template, tokenizer and draft model is approved for `<model>`. A service outside a recognised inference server may not reach the GPUs (only the `vllm-proxy-rs` proxy and the DCGM exporter may), counting a runtime, device reservation, `privileged`, `env_file` or passed-through `NVIDIA_VISIBLE_DEVICES`. Only the proxy may mount the dstack socket, no service may mount the Docker socket, and the hook and healthcheck rules above apply: each could run a model the weights check never sees. A reviewed maintenance file listed by sha256 in `APPROVED_MAINTENANCE_COMPOSES` qualifies as well. Running any service of a marked file cannot change the weights.
- **Serving-log markers** (`serving-log/<model>/<head>.json`) record the compose history of each verified CVM. `<head>` is the last entry of a rolling sha256 over its `compose_up` and `compose_down` actions (`compose_log_chain`). The marker is written only when every compose file behind the running services it reports was approved, so it cannot bless a history whose running files include an unapproved one. The gateway relay computes the same chain from the live log, finds the newest head with a marker within the last 20 compose actions, and requires every `compose_up` after it to have a serving-compose marker. With no such head it refuses.
- **The full report** is additionally written at a root key derived from the concatenated image digests. Prefer the per-digest markers, which can be checked with a single `HeadObject`.
- **Pre-verification cache**: by default a prior fully-validated result is reused for an unchanged image digest (skipping cosign + the reproducibility rebuild). Each entry is validated on load and otherwise ignored in favour of full re-verification, so the cache can never turn a failure into a pass. An entry must be well-formed, bound to the **exact requested digest**, and recorded against the **currently pinned commit**, so a stale entry cached under an older pin is rejected, and a deliberate pin bump cannot be defeated by the cache (an unpinned commit fails closed). A claimed reproducible build must itself reference the requested digest, so one image's reproducibility pass can never be replayed onto another. Set `PRE_VERIFY_DISABLED=1` to force full re-verification. The `pre-verified/` prefix must be writable only by the trusted principal (see Pre-Verification above).

### Pass criteria (summary)

Validation passes only when **all** of these are true:
- Gateway: `tdx_verified`, `os_measurements_valid`, `mrconfig_valid`, `report_data_valid`, `compose_verified`
- Each model: `gpu_verified`
- Inference (per model): `model_name_matches`, `tdx_verified`, `os_measurements_valid`, `mrconfig_valid`, `compose_hash_valid`, `proxy_report_data_valid`, `compose_manager_tdx_verified`, `same_cvm`, `report_data_valid`, `serving_yaml_verified`, `model_weights_approved`, `near_images_verified` (which includes `boot_compose_manager_verified`), `gpu_verified`
- TLS Certificate: `certificate_verified`, `fingerprint_matches`, `attestation_fingerprint_matches`, `dns_caa_verified`, and `domain` equal to the host of `BASE_URL` (`cloud-api.near.ai` in production, `cloud-stg-api.near.ai` on staging)

`image_provenance_verified` is reported for information; the gate on image provenance is `compose_verified`.

## Dependencies

- **dcap-qvl**: Intel SGX/TDX quote verification
- **cryptography**, **certifi**: TLS and certificate handling, Mozilla root store
- **pyjwt**: NVIDIA NRAS token verification
- **pycryptodomex**: Keccak-256 for ecdsa signing-address derivation
- **pyyaml**: docker-compose parsing, so only each service's own `image` counts
- **requests**: HTTP client
- **boto3**: AWS S3 client (only used when `NEAR_BUCKET_NAME` is set)
- External tools: `cosign`, `git`, Docker

See `pyproject.toml` for full dependency list.
