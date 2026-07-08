# tokenwatch

A local CLI that scans a repository for accidentally committed secrets — API keys, tokens, passwords, private keys, database connection strings — before they travel further than they should.

Runs against the current working tree, the full git history, or both. Exits non-zero on any finding, so it drops straight into a CI pipeline or a pre-commit hook as a hard gate.

## Why

Secrets leak into repositories constantly, usually by accident: a developer hardcodes an API key while debugging, commits it, pushes it. Deleting it from the latest commit doesn't remove it from git's history — the object database keeps every version of every file, and anyone with clone access can walk that history and find it. tokenwatch checks both the present and the past.

## How it works

Two independent detection layers, run together on every file:

- **Pattern matching** — regex signatures for known secret formats: AWS access keys, GitHub tokens (`ghp_`, `ghs_`, `gho_`), JWT structure, PEM private key headers, database connection strings, Slack tokens, generic bearer tokens and API key assignments.
- **Entropy scoring** — a secondary signal for high-randomness strings that don't match any known pattern. Real secrets tend to look statistically random; human-written config values don't. Catches secrets tokenwatch doesn't have a signature for yet.

Findings are redacted before they're ever stored or printed — only the first and last 4 characters of a matched secret are shown, the rest is masked.

## Install

No dependencies beyond the Python standard library and `git` on PATH. Copy the four files into your project:

```
your-project/
  tools/tokenwatch/
    scanner_core.py
    file_walker.py
    history_walker.py
    main.py
```

(Any folder name works — `tools/tokenwatch/` is just a convention. The CLI figures out its own location automatically.)

## Usage

Scan the current working tree:
```bash
python tools/tokenwatch/main.py scan .
```

Scan working tree **and** full git history — catches secrets that were committed and later deleted:
```bash
python tools/tokenwatch/main.py scan . --history
```

Same as `scan`, but also writes a timestamped JSON report to `reports/`:
```bash
python tools/tokenwatch/main.py report . --history
```

Check the exit code if scripting around it:
```bash
python tools/tokenwatch/main.py scan . --history
echo $?   # 0 = clean, 1 = findings
```

## Generating the GitHub Actions workflow

```bash
python tools/tokenwatch/main.py init
```

This detects tokenwatch's own location relative to your repo root and writes a correctly pathed `.github/workflows/tokenwatch.yml` — no manual editing needed regardless of which folder you put tokenwatch in. Won't overwrite an existing workflow unless you pass `--force`.

Once committed and pushed, the workflow runs `scan . --history` on every push and pull request, using `fetch-depth: 0` to fetch full commit history (required — Actions does a shallow clone by default, which would make `--history` silently find nothing).

## Suppressing false positives

Add a `.tokenwatchignore` file at your project root — one glob pattern per line, `#` comments allowed:
```
tests/*
*.example
fixtures/*
```
Patterns match both the full relative path and the bare filename, so both path-based and extension-based rules work as expected. Note: patterns don't support `**` recursive matching — `tests/*` only matches files directly inside `tests/`, not nested subdirectories.

## Scope

tokenwatch deliberately does not:
- Watch a repository live / continuously (no long-running process, no infrastructure)
- Rotate or revoke leaked secrets automatically
- Make any network calls — all analysis is local, reading only from the filesystem and the local `.git` directory

## License

GPLv2 — see [LICENSE](LICENSE).