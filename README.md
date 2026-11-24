# Paperclip B2 isolated build recipe

Manual, standard public GitHub-hosted Ubuntu24.04 CI only. This repository contains a small dependency patch and a controller-only container recipe; it downloads and verifies upstream Paperclip v2026.1117.0 (commit c0f132898d2a2677312d8c72096187b27a3d9a38).

Pinned changes: body-parser2.4.0, Sharp0.35.5, proxy-addr2.0.8 and path-to-regexp8.4.2. No application core changes. Ubuntu24.04 snapshot20261124T000000Z supplies the OpenSSH security backport. Full pins and checksums are in pins.json.

The workflow performs one resource/attestation preflight and at most one full build. It exports an OCI layout locally, checks contents, secrets and SBOM/provenance before any registry publication, and never starts Paperclip or a provider executor. No paid runner, hosted cache or Actions artifact storage. No privileged builder or security-profile bypass. Inadequate resources/capabilities stop the job.

The repository and image are experimental build candidates, not a security certification or deployment. Built-in provider SDK modules remain; absence of global CLIs is not a universal provider deny gate. Remaining advisories require final-image analysis before a separately authorized runtime test.

Upstream: https://github.com/paperclipai/paperclip. Upstream code is downloaded from its official immutable archive; MIT license and attribution are retained. This repository contains no account credentials or deployment data.

## First bounded preflight

The single initial hosted job measured4CPU, about15.3GiB RAM and88.4GiB free disk. No SDK cleanup was needed. The estimated peak envelope is42.4GiB with a45GiB admission gate; this is a planning estimate, not measured build usage.

No full build or registry publication occurred: the existing Docker containerd image store was disabled. The recipe intentionally does not reconfigure the Docker daemon or use a privileged builder. The first diagnostic also used an unsupported `buildx inspect --format` option; that parser is corrected here without another job, and its null result is not evidence that a default builder was absent. Local OCI/SBOM/provenance capability remains unqualified until a separately approved CI configuration change/test.
