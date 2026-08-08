# CI Control Plane Installation

The control plane source package is `WORKSPACE-CI/control-plane`. The installed
binary is independently built, verified, and root-owned. It must not be built
or executed as root from `WORKSPACE-CI`, `WORKSPACE-GUARD`, or an active CI
release.

Install the standalone package supplied by the operator or image build at:

```text
/usr/libexec/workspace-ci-control
```

Do not use `make install-hooks`, `make install-ci-control`, or any helper from
the agent-writable source checkout as the promotion mechanism.

Create `/etc/workspace-ci/control.yaml` as root-owned mode `0600`:

```yaml
deployment_root: ${WORKSPACE_ROOT}/projects
release_root: ${WORKSPACE_ROOT}/projects/CI.releases
repository_cache: /var/lib/workspace-ci-control/repository.git
upstream_repository: git@github.com:Independent-AI-Labs/WORKSPACE-CI.git
upstream_ref: refs/heads/main
validator_n: /usr/libexec/workspace-ci-validator-n
validator_n_plus_1: /usr/libexec/workspace-ci-validator-n-plus-1
hook_validator: /usr/libexec/workspace-ci-hook-validator
health_check: /usr/libexec/workspace-ci-health-check
hook_installer: /usr/libexec/workspace-ci-hook-installer
hook_abi: 1
```

The control plane rejects missing or insecure configuration and refuses
environment-variable or command-line overrides of these values. It fetches the
exact upstream revision, validates it without executing candidate helpers as
root, seals a release, and atomically replaces the `CI` symlink.

## First Migration

Before activation, the tool must preserve the existing deployment exactly:

1. Create a prepared release outside `CI`.
2. Create `CI.next` pointing to that release.
3. Atomically exchange `CI` and `CI.next`.
4. Rename the exchanged original directory to `CI.backup`.
5. Verify and seal `CI.backup`.

If activation or health checks fail, atomically exchange `CI` and `CI.backup`.
Never copy files over the live `CI` path.

## Normal Operations

```bash
/usr/libexec/workspace-ci-control prepare
/usr/libexec/workspace-ci-control activate sha256-<tree-digest>
/usr/libexec/workspace-ci-control rollback
/usr/libexec/workspace-ci-control recover
```

`prepare` never changes the active release. `activate` retains the old release
as `CI.previous`; failed health or hook installation restores it atomically.
`rollback` selects the retained release without rebuilding or editing it.
