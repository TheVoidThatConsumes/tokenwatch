# tokenwatch — DECISIONS.md

Seeded from the gossamer-suite integration audit (Aug 2026). No prior
`DECISIONS.md` existed before this — this is the first version, not a
placeholder, and should be extended the same way going forward: real
decisions with real rationale, not just outcomes.

## License: GPL-2.0-only → Apache-2.0

Relicensed deliberately to match the gossamer-suite standard (Apache 2.0
code / CC BY 4.0 docs), not an accident of copy-paste. `LICENSE` replaced
with the canonical Apache 2.0 text; `pyproject.toml`'s `license` field set
to the SPDX string form `"Apache-2.0"` (PEP 639), matching VSac's form —
not the deprecated table form.

## `--json` output: added to `scan` (not `report`)

`registry.py`'s `ToolSpec` for tokenwatch invokes `scan --history --json`,
so `--json` was added as a flag on the `scan` subcommand rather than
building a separate envelope path off `report`. `report` still writes its
own (non-schema) file under `reports/` for local/manual use — untouched.

**stdout/stderr split**: with `--json` set, stdout carries *only* the
envelope JSON. Everything else that `scan` normally prints — the
first-run workflow-autogen notice, the entrypoint-detection warning, tamper
warnings — moves to stderr. This was necessary because `aggregate.py`
parses `proc.stdout` directly with `json.loads()`; any stray print on
stdout breaks that parse and gets misreported as a tool crash rather than
what it actually is.

**id scheme**: `TW-<SUBTYPE>-NNN`, single category (`secret-exposure`,
per `categories.json`), subtype per detected secret type (`AWS`, `GITHUB`,
`BEARER`, `JWT`, `PRIVATEKEY`, `DBCONN`, `SLACK`, `GENERICKEY`, `GITLAB`,
`ENTROPY`, falling back to `GENERIC` for any future pattern label not yet
mapped). `NNN` is a per-subtype counter within a single run (zero-padded
to 3), not a global finding index — mirrors pipewatch's `PW-INJ-001` shape.

**severity**: straight case-fix (`high`→`HIGH` etc.) via `envelope.py`'s
`SEVERITY_MAP`. No remapping — the true-positive test during the audit
(planted AWS key) confirmed the underlying severity judgment was already
correct, only the casing was schema-incompatible.

**location convention**: `<path>:<line>` for working-tree findings,
`<commit_sha>:<path>:<line>` for git-history findings. Kept as a single
opaque string per the schema's own instruction that consumers must never
parse or structurally compare `location` across tools — the commit-sha
prefix is there for human legibility only, not for programmatic splitting.

**ordering for deterministic ids**: findings are sorted by severity rank,
then file, then line before subtype counters are assigned, so that ids are
stable across repeated runs on unchanged input (matters for anyone diffing
successive `--json` outputs).

## Known open items (not fixed in this pass — logged, not silently patched)

- **cwd/path divergence**: `find_repo_root()` is anchored to `Path.cwd()`,
  independent of the `path` positional argument passed to `scan`. If
  `scan` is ever invoked with a `cwd` different from the target `path`
  (not how `aggregate.py` calls it today — it sets `cwd=repo` and passes
  `.` — but worth guarding against), workflow tamper-detection would run
  against the wrong repo. Flagged, not yet fixed.
- **Shallow-clone truncation**: `history_walker.py`'s `git log --reverse`
  has no shallow-repo detection. Under a `--depth 1` CI checkout, history
  scanning silently returns fewer commits than actually exist upstream —
  no error, no warning. Flagged, not yet fixed.
- **Socket-hard-block runtime test**: static grep for network-capable
  imports is clean (verified: real `import`/`from` statements only, not
  substring matches), but the runtime sockets-blocked equivalence test
  from the suite audit checklist has not yet been run.
- **No test suite** existed before this audit; `envelope.py`'s conversion
  logic was validated manually against the real schema files and
  `dashboard.html`'s actual `validateEnvelope`/`resolveTool` functions
  during this pass, but that validation isn't yet captured as a repeatable
  test.