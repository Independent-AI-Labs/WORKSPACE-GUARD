# WORKSPACE-GUARD: Canonical reference sources

This directory holds offline copies of the public sources that ground the
WORKSPACE-GUARD system-binary lockdown program (the SUID / capability / CVE
catalog + sandbox best-practices stack). Every non-obvious claim in
`docs/RESEARCH-SYSTEM-BINARIES.md`, `docs/specifications/SPEC-BINARY-LOCK.md`,
`docs/specifications/SPEC-CAP-THROTTLE.md`, `docs/specifications/SPEC-SANDBOX.md`,
and `docs/specifications/SPEC-AUDIT.md` can be traced back to one of the files
listed below. The CVE catalog quotes advisory text verbatim wherever the claim
is non-obvious.

The sync script `scripts/sync-gtfobins` re-fetches the canonical GTFOBins list
and `misc/suid.list` on every run; the cached HTML files below are the inputs
to that script. They are committed so the build is reproducible offline.

## Cached inputs (used by `scripts/sync-gtfobins`)

| URL | Local file | Used for |
|-----|------------|----------|
| https://gtfobins.github.io/#+suid           | gtfobins-suid.html            | 250+ GTFOBins SUID-exploitability list |
| https://gtfobins.github.io/#+sudo           | gtfobins-sudo.html            | GTFOBins sudo-gated binary list |
| https://gtfobins.github.io/#+capabilities   | gtfobins-caps.html            | GTFOBins capability-exploitability list |
| https://raw.githubusercontent.com/konstruktoid/hardening/master/misc/suid.list | konstruktoid-suid-list.txt | CIS-aligned curated SUID baseline |
| https://man7.org/linux/man-pages/man7/capabilities.7.html | capabilities.7.html | authoritative Linux capabilities(7) page |

## CVE / advisory references

| URL | Local file | Used for |
|-----|------------|----------|
| https://www.sudo.ws/security/advisories/chroot_bug/                  | sudo-chroot-CVE-2025-32463.html      | sudo `--chroot` LPE advisory (CVE-2025-32463) |
| https://nvd.nist.gov/vuln/detail/CVE-2021-4034                       | NVD-CVE-2021-4034.html               | PwnKit pkexec OOB argv (CVE-2021-4034) |
| https://nvd.nist.gov/vuln/detail/CVE-2021-3156                       | sudo-Baron-Samedit-CVE-2021-3156.html| sudo Baron Samedit heap overflow |
| https://nvd.nist.gov/vuln/detail/CVE-2025-32463                      | NVD-CVE-2025-32463.html              | sudo `--chroot` NVD entry |

## Sandbox & capability research (ground for SPEC-SANDBOX + SPEC-CAP-THROTTLE)

| URL | Local file | Used for |
|-----|------------|----------|
| https://www.systemshardening.com/articles/linux/linux-capability-hardening/       | systemshardening-cap-hardening.html | per-service cap allowlist table |
| https://www.systemshardening.com/articles/linux/linux-file-immutability-chattr/   | systemshardening-chattr.html        | `chattr +i` and CAP_LINUX_IMMUTABLE model |
| https://www.systemshardening.com/articles/linux/dm-verity/                        | systemshardening-dm-verity.html     | dm-verity root + dm-integrity state |
| https://yunolay.com/suid-sgid-abuse/                                             | yunolay-suid-sgid-abuse.html       | SUID/SGID local privesc taxonomy |
| https://yunolay.com/linux-capabilities-abuse/                                    | yunolay-caps-abuse.html            | setuid + dac_read_search abuse |
| https://arxiv.org/html/2605.26298v1                                               | sandlock-arxiv.html                | Sandlock rootless sandbox design |
| https://www.elastic.co/security-labs/unlocking-power-safely-privilege-escalation-via-linux-process-capabilities | elastic-cap-escalation.html | cap escalation detection telemetry |
| https://github.com/dev-sec/cis-dil-benchmark/blob/master/controls/6_1_system_file_permissions.rb | cis-dil-benchmark-suid-rb.html | CIS DIL 6.1.13/6.1.14 SUID review control |

## Portable PDFs (human review of the cleanest sources)

| Source HTML / TXT | Generated PDF |
|-------------------|---------------|
| sudo-chroot-CVE-2025-32463.html | sudo-chroot-CVE-2025-32463.pdf |
| konstruktoid-suid-list.txt      | konstruktoid-suid-list.pdf |

## Regeneration

- To re-fetch all canonical HTML/TXT inputs above: `make sync-gtfobins` (defined in the repo `Makefile`).
- To regenerate the PDF review copies from the cleanest sources: `make sync-pdf`.
- HTML files for sites that render with client-side JavaScript (NVD, GitHub)
  are committed as-received from `curl`, so the rendering is what the script
  sees. The CVE quotes used by the docs are taken from the advisory prose
  inside the cached HTML, not the rendered DOM.

## Provenance policy

- No URL in the table above is guessed. Each URL was either already cited in
  the existing `RESEARCH.md` (Copy Fail, PwnKit, GTFOBins, Zylos) or fetched
  directly from the search results shown in the audit transcript.
- The CVE catalog in `docs/RESEARCH-SYSTEM-BINARIES.md` cites the local file
  it quotes from, so a reviewer can verify the text against the cached
  advisory without network access.
- `scripts/sync-gtfobins --verify` re-downloads every canonical source and
  emits a SHA-256 manifest (`res/canonical-sources.sha256`) so drift between
  the cached copy and the canonical URL is detected.