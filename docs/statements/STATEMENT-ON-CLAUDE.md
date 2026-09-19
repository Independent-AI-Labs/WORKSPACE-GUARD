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

Claude models and the Claude Code agent tool are NOT APPROVED as
development tooling for the WORKSPACE federated system: no WORKSPACE
code may be written, reviewed, modified, or committed with them. This
is a final position on tooling, not a temporary suspension. Transport
components that merely proxy requests to Anthropic services are not
development tooling and are outside this statement's scope.

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
   providers and agents; developing it while consuming Anthropic
   services sits in the restricted category of that clause. A license
   that presumes against the project's own existence cannot govern its
   development. (Proxying requests to Anthropic is ordinary customer
   use, not development; see Consequences.)

4. **Watermarking.** Since 2026-08-02 Claude output carries a
   SynthID-Text style watermark applied globally, with no opt-out, and
   verifiable only through Anthropic's restricted detection API. Every
   Claude-generated token in WORKSPACE pipelines would carry an
   unremovable third-party provenance channel. For sovereign code and
   content production this is disqualified on its own; combined with
   grounds 1 through 3 it closes the case.

## Consequences

- WORKSPACE-GATEWAY is a transport proxy. Its Anthropic provider work
  (claude-gw.sh, REQ-PROVIDER-ANTHROPIC, SPEC-PROVIDER-ANTHROPIC,
  related OAuth plugins) is proxy infrastructure, not development
  tooling, and is NOT affected by this statement; it may be extended,
  wired, and merged like any other provider.
- Claude models, Claude Code, and Anthropic-dependent coding assistants
  must not be used to write, review, modify, or commit WORKSPACE code,
  and must not be wired into WORKSPACE engineering pipelines or the git
  boundary. Reviews reject such changes.
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
