# tokenwatch

A local CLI that scans a repository for accidentally committed secrets — API keys, tokens, passwords, private keys, database connection strings — before they travel further than they should.

Runs against the current working tree, the full git history, or both. Exits non-zero on any finding or if the CI workflow has been tampered with, so it drops straight into a pipeline or pre-commit hook as a hard gate.

## Why tokenwatch?

Secrets leak into repositories constantly, usually by accident: a developer hardcodes an API key while debugging, then commits and pushes it. Deleting it from the latest commit doesn't remove it from git's history — the object database keeps every version of every file, and anyone with clone access can walk that history and find it. tokenwatch checks both the present and the past versions for these secrets.

## How it works

Two independent detection layers, run together on every file:

- **Pattern matching** — regex signatures for known secret formats: AWS access keys, GitHub tokens (`ghp_`, `ghs_`, `gho_`), GitLab runner registration tokens (`GR1348`), JWT structure, PEM private key headers, database connection strings, Slack tokens, generic bearer tokens and API key assignments.
- **Entropy scoring** — a secondary signal for high-randomness strings that don't match any known pattern (threshold: 4.5 bits/char). Real secrets tend to look statistically random; human-written config values do not. File and module paths are filtered out before scoring — they look random but aren't secrets. Catches secrets tokenwatch doesn't have a signature for yet.

Findings are redacted before they're ever stored or printed — only the first and last 4 characters of a matched secret are shown, the rest is masked.

## Install

There are no dependencies beyond the Python standard library and `git` on PATH. Copy the four files into your project:

```
your-project/
  tools/tokenwatch/
    scanner_core.py
    file_walker.py
    history_walker.py
    main.py
```

Any folder name works — `tools/tokenwatch/` is just a convention. The CLI figures out its own location automatically.

## Getting started

After copying the files in, verify the tool is working correctly in your environment:

```bash
python tools/tokenwatch/main.py verify
```

This runs both detection layers against synthetic inputs and confirms the false-positive suppression is working. If everything passes, you're ready to scan.

## Usage

**Verify the installation:**
```bash
python tools/tokenwatch/main.py verify
```

**Scan the working tree:**
```bash
python tools/tokenwatch/main.py scan .
```

**Scan working tree and full git history** — catches secrets that were committed and later deleted:
```bash
python tools/tokenwatch/main.py scan . --history
```

**Save a report** — same as scan but writes a timestamped JSON to `reports/` inside the scanned project:
```bash
python tools/tokenwatch/main.py report . --history
```

**Check the exit code if scripting around it:**
```bash
python tools/tokenwatch/main.py scan . --history
echo $?   # 0 = clean, 1 = findings or tamper warning
```

## GitHub Actions integration

The first time you run `scan`, tokenwatch automatically generates `.github/workflows/tokenwatch.yml` if it doesn't already exist — no separate setup step needed. It detects its own location relative to your repo root and writes the correct path into the workflow.

You'll see:
```
tokenwatch: no workflow found — generated .github/workflows/tokenwatch.yml
  run: git add .github/workflows/tokenwatch.yml
       git commit -m 'add tokenwatch CI workflow'
       git push
```

Commit and push the generated file to activate the CI gate. Once active, the workflow runs `scan . --history` on every push and pull request.

To regenerate or restore a workflow manually:
```bash
python tools/tokenwatch/main.py init           # generate if missing
python tools/tokenwatch/main.py init --force   # overwrite existing (shows diff first)
```

`fetch-depth: 0` is set in the generated workflow and is required — without it, Actions performs a shallow clone and `--history` silently finds nothing.

## Tamper detection

tokenwatch hashes its own workflow file when it generates it and stores that hash in `.tokenwatch_state` at your repo root. On every subsequent scan, it:

1. Recomputes the hash and compares — any content change is flagged
2. Checks the `run:` line still calls `scan . --history` — catches a weakened command even if the hash was manually updated to cover it

A tamper warning is printed to stderr before the scan runs and causes the process to exit 1, the same as a real finding. To restore a tampered workflow:

```bash
python tools/tokenwatch/main.py init --force
```

Commit both `.tokenwatch_state` and the restored workflow file.

## Suppressing false positives

**Inline suppression** — append `# tokenwatch: ignore` to any line to exclude it from working-tree findings:

```python
key = "AKIAABCDEFGHIJKLMNOP"  # tokenwatch: ignore
```

Applies to working-tree scans only. Findings from `--history` cannot be suppressed inline — they exist in committed blobs that are immutable.

**Ignore file** — add a `.tokenwatchignore` at your project root, one glob pattern per line, `#` comments allowed:

```
tests/*
*.example
fixtures/*
```

Patterns match both the full relative path and the bare filename. Note: `**` recursive matching is not supported — `tests/*` only matches files directly inside `tests/`, not nested subdirectories.

## What gets skipped

tokenwatch automatically skips files and directories that produce noise rather than signal:

**Directories:** `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`, `build`, `.tox`, `.mypy_cache`, `.pytest_cache`, `vendor`, `target`

**Binary extensions:** image, audio, video, archive, compiled, and font formats — and database files (`.db`, `.sqlite`, `.sqlite3`)

**Minified and bundled assets:** any filename containing `.min.`, `.bundle.`, `.chunk.`, `.dev.`, or `.prod.` (e.g. `vendor.bundle.dev.js`, `components.min.js`) — these are machine-generated and generate large volumes of entropy false positives from webpack chunk paths and sourcemap hashes

**Binary content:** extensionless files are sniffed for null bytes and skipped if found — covers build cache blobs and compiled assets that have no extension

**Oversized files:** anything over 5 MB

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean — no findings, workflow intact |
| `1`  | Findings present, or workflow tamper detected |

## Scope

tokenwatch deliberately does not:
- Watch a repository live or continuously
- Rotate or revoke leaked secrets automatically
- Make any network calls — all analysis is local, reading only from the filesystem and the local `.git` directory

## License

GPLv2 — see [LICENSE](LICENSE).