# Dependency Audit

## Scope

This audit covers first-party Guard test images, test dependencies, Podman
runners, and host package declarations. Rust dependencies remain owned by
Cargo manifests and lockfiles.

## Current Registries

| Registry | Current purpose | Gap |
|---|---|---|
| `config/system-deps.yaml` | Host apt/brew package names and checks | Does not own image or release pins |
| `config/dependency_excludes.yaml` | Dependency-check exclusions | Does not own versions |
| `res/binary-lock.yaml` | Generated host binary baseline | Not an installer dependency catalog |
| `res/cve-catalog.yaml` | Generated CVE metadata | Not an installer dependency catalog |

## Hardcoded Artifact Pins

- `Containerfile.test` contains the Ubuntu `22.04` base image and bats-core
  `1.13.0` release.
- `scripts/podman/ensure-machine.sh` explicitly pulls Ubuntu `22.04`.
- Tier runners and the Makefile repeat the local image tag
  `workspace-guard-test:ubuntu-22.04`.

These are executable dependency references with no common owner. The same
Ubuntu release is represented in multiple files, so version drift is possible.

## Required End State

Create `res/dependency-pins.yaml` with an OCI image section and a bats-core
artifact section. Make the build entry point resolve the image and bats version
from the catalog, pass required build arguments to `Containerfile.test`, and
make all runner scripts consume the same derived image tag. The dependency
scanner must validate every declared reference and reject independent literals.
