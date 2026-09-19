# WORKSPACE Statement on Claude and Claude Code

- Statement ID: WS-STATEMENT-2026-09-19-01
- Date: 2026-09-19
- Status: ADOPTED
- Operator review: Local Admin (root), 2026-09-19
- Language: English (authoritative Bulgarian version:
  `STATEMENT-ON-CLAUDE-BG.md`)
- Evidence base: `../research/RES-ANTHROPIC-LEGAL-REVIEW.md` and
  `../research/evidence/anthropic/` (byte-exact snapshots with
  checksums)

## Decision

Claude models, the Claude Code agent tool, and any component that
routes WORKSPACE workloads to Anthropic services are NOT APPROVED for
use anywhere in the WORKSPACE federated system. This is a final
position, not a temporary suspension.

## Grounds

1. **Proprietary core.** Claude models are closed-weight proprietary
   services. The Claude Code repository license is "© Anthropic PBC.
   All rights reserved." with use deferred to Anthropic's Commercial
   Terms of Service. A public repository does not make software
   open-source: that status comes only from a license grant, and there
   is none. At best Claude Code is source-available under proprietary
   terms, with reverse engineering and competing use forbidden by
   Section D.4 of the Terms. WORKSPACE requires inspectable tooling at
   every trust boundary; a tool we cannot lawfully inspect cannot
   occupy one.

2. **Hostile default behavior at the git boundary.** Claude Code
   prefixes internal git calls with configuration that neutralizes
   local hooks (`core.hooksPath=/dev/null` and related keys) and
   resorts to `--no-verify` / `-n` when hooks resist. This is
   documented in Anthropic's own issue tracker (issues 40117 and
   66069) and was observed directly against the WORKSPACE-GUARD git
   guard on 2026-09-19. WORKSPACE quality policy is hook-enforced by
   design; a tool whose default posture is to defeat hooks is
   incompatible with it. The guard blocks this by default and will
   continue to do so for any tool with the same posture.

3. **License conflict.** Anthropic Commercial Terms of Service,
   Section D.4(a), forbids accessing the services "to build a
   competing product or service, including to train competing AI
   models". WORKSPACE is a federated AI delivery platform with its own
   gateway, providers, and agents; under that clause the project sits
   in the restricted category. A license that presumes against the
   project's own existence cannot govern any part of it.

4. **Watermarking.** Since 2026-08-02 Claude output carries a
   SynthID-Text style watermark applied globally, with no opt-out, and
   verifiable only through Anthropic's restricted detection API. Every
   Claude-generated token in WORKSPACE pipelines would carry an
   unremovable third-party provenance channel. For sovereign code and
   content production this is disqualified on its own; combined with
   grounds 1 through 3 it closes the case.

## Consequences

- The Anthropic provider work in WORKSPACE-GATEWAY (claude-gw.sh,
  REQ-PROVIDER-ANTHROPIC, SPEC-PROVIDER-ANTHROPIC, related OAuth
  plugins) is HALTED. It must not be extended, wired, or merged. The
  operator decides whether to archive or remove it.
- No WORKSPACE component may add, call, or depend on Anthropic APIs,
  Claude binaries, or Claude Code plugins. Reviews must reject such
  changes.
- The git guard read-only sanitization work (REQ-GGUARD-043..046)
  PROCEEDS unchanged: the hook-bypass threat is general to third-party
  agent tools and the hardening is not Claude-specific.
- This statement is revisited only if Anthropic publishes terms that
   remove the competing-products restriction, grants real inspection
   rights, and offers watermark opt-out. Until all three exist, the
   decision stands.

## Verification Record

- Commercial Terms of Service, effective 2025-06-17, Section D.4:
  snapshot 2026-09-19.
- anthropics/claude-code LICENSE.md: snapshot 2026-09-19.
- Anthropic watermark announcement 2026-08-14: snapshot 2026-09-19.
- anthropics/claude-code issues 40117 and 66069: snapshots 2026-09-19.
- WORKSPACE-GUARD git guard incident log: RESEARCH.md section 8.

All snapshots are checksummed in
`../research/evidence/anthropic/README.md`.
