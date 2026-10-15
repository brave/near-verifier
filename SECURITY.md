# Security Policy

## Reporting a Vulnerability

Report via **https://hackerone.com/brave**. Please do not open a public issue for a security finding.

## Scope

This repository is a *verifier*: it checks that NEAR AI Cloud is running the code it claims to, inside genuine Intel TDX and NVIDIA confidential-compute hardware. Findings fall into three buckets, and only the first is fixed here. For what a run sends over the network and whom it contacts, see the [Privacy](README.md#privacy) section of the README.

**1. The verifier accepts something it should reject.** In scope, and treated as high severity: a false pass defeats the entire purpose of this tool. Examples:

- A way to make a TDX quote, SLSA provenance, reproducible-build, GPU-attestation, or TLS check report success without the underlying property actually holding.
- A quote that is not bound to the TLS channel the client talks to, or that can be replayed from another backend or an earlier run.
- Forging an S3 marker. The verifier reads `pre-verified/` entries to skip re-verifying an image; Brave's gateway relay ([brave/ai-gateway](https://github.com/brave/ai-gateway)) reads `signing-keys/`, `serving-compose/` and `serving-log/` to admit traffic. Note the trust boundary: all four prefixes must be writable only by the verifier and pre-verify principals (in Brave's deployment, internal CI roles). A finding that assumes write access to them is a deployment issue (bucket 2), not a verifier bypass, unless it defeats the entry-integrity checks in `_cached_result_is_trustworthy`.
- Accepting a platform TCB status, measurement, or pin set broader than documented.

**2. A weakness in Brave's deployment of NEAR AI Cloud.** In scope via HackerOne, but not fixed in this repository.

**3. A weakness in NEAR's services** (`cloud-api`, `inference-proxy`, `compose-manager`, `cvm-ingress`, or the model runtime). Report to NEAR; we will help coordinate disclosure.

## Not a vulnerability

- **A failing verification run.** If this tool reports a mismatch, it is working as intended. A failure means the live deployment does not match the audited pins in `verifier/config.py`, usually because NEAR shipped a new build and the pins have not caught up yet. Please don't file that as a vulnerability.
- **Anything outside the attested boundary.** Reproducible builds prove the running bytes match the audited source; they do not prove that source is free of backdoors. See the trust assumptions in the README for what this tool does and does not establish.

## Supported versions

The `master` branch is the only supported version. This tool verifies a live service, so an older checkout carries stale pins and will report failures that reflect its own age rather than a problem with the deployment.
