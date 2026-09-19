# Evidence Index: Anthropic / Claude Code Legal and Behavioral Review

Fetch date for all items: 2026-09-19 (UTC). Fetched by direct HTTP GET
(curl) from the live public sources listed below. Each item is stored
base64-encoded (76-column wrapping) so the byte-exact payload is
recoverable with `base64 -d <file>` while every artifact in this
repository remains valid UTF-8 text. The digests below are of the
DECODED originals; decoding any stored file must reproduce them.

## Items

| File | Source URL | Uncompressed SHA-256 |
|------|------------|----------------------|
| `anthropic-commercial-terms-of-service-2025-06-17.html.b64.txt` | https://www.anthropic.com/legal/commercial-terms | `1fb57187fdec54db0538e3ff8397bdf395b7b52543960e1affbf1d5d24163a15` |
| `claude-code-repo-LICENSE-2026-09-19.md.b64.txt` | https://raw.githubusercontent.com/anthropics/claude-code/main/LICENSE.md | `728158fd1037143fad6907e8fa34804177e598b7326519503fe83cafdef849e6` |
| `anthropic-claude-text-watermark-2026-08-14.html.b64.txt` | https://www.anthropic.com/news/claude-text-watermark | `dce25ecf6a2920c048f4205dc14363cf1921ca78a6276b21e636bf56feceeae9` |
| `claude-code-issue-40117-2026-09-19.json.b64.txt` | https://api.github.com/repos/anthropics/claude-code/issues/40117 | `71a4a20ff43f9e412e0d5091f4e503ac851afe8372b71689abff801b742f78af` |
| `claude-code-issue-66069-2026-09-19.json.b64.txt` | https://api.github.com/repos/anthropics/claude-code/issues/66069 | `85c0cb62e4fb353cf98865de23a46769f454e50d68ce35887783d11e24893258` |

## Notes

- The Commercial Terms of Service snapshot is the version effective
  2025-06-17, as served by anthropic.com on the fetch date. Section
  D.4 (Use Restrictions) is the clause relied on by the WORKSPACE
  statement on Claude (competing products restriction).
- The LICENSE.md snapshot of the `anthropics/claude-code` repository
  contains no open-source license grant; it reserves all rights to
  Anthropic PBC and defers to the Commercial Terms of Service.
- The watermark announcement is the Anthropic blog post of 2026-08-14
  describing SynthID-Text based watermarking of Claude text output.
- The two GitHub issue snapshots are first-party records from the
  official Anthropic repository documenting Claude Code hook-bypass
  behavior reports (issues now closed).

See `../../RES-ANTHROPIC-LEGAL-REVIEW.md` for the analysis and
`../../../statements/` for the resulting WORKSPACE statements.
