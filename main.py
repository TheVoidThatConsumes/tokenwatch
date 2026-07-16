"""
main.py — tokenwatch CLI entrypoint

Commands:
  scan <path> [--history]   scan working tree, optionally + git history
  report <path> [--history] same as scan, but also writes JSON to reports/
  init [--force]            generate the GitHub Actions workflow file

Exit code 1 if any findings are present OR if workflow tampering is detected.

On first run, scan automatically generates the GitHub Actions workflow
if one doesn't already exist — no need to run init manually.

Tamper detection: tokenwatch hashes its own workflow file at generation
time and stores that hash in .tokenwatch_state. On every subsequent scan
it recomputes the hash and checks that the run: line still calls
scan . --history. Any deviation is flagged before the scan runs.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from file_walker import scan_directory
from history_walker import scan_history, is_git_repo

STATE_FILE    = ".tokenwatch_state"
REQUIRED_ARGS = "scan . --history"   # what the workflow run: line must contain


WORKFLOW_TEMPLATE = """\
name: tokenwatch

on: [push, pull_request]

jobs:
  tokenwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # full history — needed for --history scan

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: run tokenwatch
        # path is relative to repo root — update this if you move tokenwatch
        run: python {entrypoint} scan . --history
"""


# ---------------------------------------------------------------------------
# Repo root + entrypoint detection
# ---------------------------------------------------------------------------

def find_repo_root(start):
    """Walk upward from start looking for a .git directory."""
    current = Path(start).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def detect_entrypoint(repo_root):
    """Return the path to main.py relative to repo_root as a posix string."""
    script_path = Path(__file__).resolve()
    try:
        return script_path.relative_to(repo_root).as_posix()
    except ValueError:
        print(
            "warning: could not determine tokenwatch's path inside the repo — "
            "defaulting to 'tools/tokenwatch/main.py'. "
            "Edit the run: line in the generated workflow if that's wrong.",
            file=sys.stderr,
        )
        return "tools/tokenwatch/main.py"


# ---------------------------------------------------------------------------
# State file — persists workflow hash between runs
# ---------------------------------------------------------------------------

def state_path(repo_root):
    return repo_root / STATE_FILE


def load_state(repo_root):
    sp = state_path(repo_root)
    if not sp.exists():
        return {}
    try:
        return json.loads(sp.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_state(repo_root, state):
    state_path(repo_root).write_text(json.dumps(state, indent=2))


# ---------------------------------------------------------------------------
# Workflow hashing
# ---------------------------------------------------------------------------

def hash_file(path):
    """SHA-256 hash of a file's contents."""
    content = Path(path).read_text(errors="ignore")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Workflow generation
# ---------------------------------------------------------------------------

def workflow_path(repo_root):
    return repo_root / ".github" / "workflows" / "tokenwatch.yml"


def generate_workflow(repo_root, entrypoint):
    """Write the workflow file, hash it, and save the hash to state."""
    wf_path = workflow_path(repo_root)
    wf_path.parent.mkdir(parents=True, exist_ok=True)
    wf_path.write_text(WORKFLOW_TEMPLATE.format(entrypoint=entrypoint))

    # store the hash immediately so the next scan has a baseline to compare
    state = load_state(repo_root)
    state["workflow_hash"] = hash_file(wf_path)
    state["entrypoint"]    = entrypoint
    state["generated"]     = datetime.now(timezone.utc).isoformat()
    save_state(repo_root, state)

    return wf_path


def show_diff(existing_text, new_text):
    existing_lines = existing_text.splitlines()
    new_lines      = new_text.splitlines()
    removed = [line for line in existing_lines if line not in set(new_lines)]
    added   = [line for line in new_lines if line not in set(existing_lines)]
    if not removed and not added:
        print("  (no content changes)")
        return
    for line in removed:
        print(f"  - {line}")
    for line in added:
        print(f"  + {line}")


def auto_init(repo_root):
    """Generate the workflow on first run. Silent if it already exists."""
    wf_path = workflow_path(repo_root)
    if wf_path.exists():
        return

    entrypoint = detect_entrypoint(repo_root)
    generate_workflow(repo_root, entrypoint)

    print(f"tokenwatch: no workflow found — generated {wf_path}")
    print(f"  run: git add {wf_path.relative_to(repo_root)}")
    print(f"       git commit -m 'add tokenwatch CI workflow'")
    print(f"       git push")
    print()


# ---------------------------------------------------------------------------
# Tamper detection — called before every scan
# ---------------------------------------------------------------------------

def check_workflow_integrity(repo_root):
    """Check the workflow file hasn't been modified since it was generated.

    Two checks:
      1. Hash — SHA-256 of the current file vs the stored hash. A mismatch
         means the file content changed, regardless of what changed.
      2. run: line — confirms the scan command hasn't been weakened. Even if
         the hash somehow matched, this is a belt-and-suspenders check that
         the actual command being run on CI is still the full --history scan.

    Returns a list of tamper warning strings, empty if everything is clean.
    """
    wf_path  = workflow_path(repo_root)
    warnings = []

    if not wf_path.exists():
        return []  # workflow doesn't exist yet — auto_init will handle it

    # read once — used for both hash check and run: line check
    content = wf_path.read_text(errors="ignore")
    state   = load_state(repo_root)

    # Check 1 — hash
    stored_hash = state.get("workflow_hash")
    if not stored_hash:
        # State file missing or predates tamper detection — hash current file
        # and save as baseline. Trust it this once.
        state["workflow_hash"] = hash_file(wf_path)
        state["entrypoint"]    = detect_entrypoint(repo_root)
        state["generated"]     = datetime.now(timezone.utc).isoformat()
        save_state(repo_root, state)
    else:
        current_hash = hash_file(wf_path)
        if current_hash != stored_hash:
            warnings.append(
                f"workflow file hash mismatch — file may have been tampered with\n"
                f"  stored : {stored_hash[:16]}...\n"
                f"  current: {current_hash[:16]}..."
            )

    # Check 2 — run: line still contains the full scan command
    run_lines = [
        line.strip() for line in content.splitlines()
        if line.strip().startswith("run:")
    ]
    if not run_lines:
        warnings.append("workflow run: line is missing — the scan step may have been removed")
    else:
        for run_line in run_lines:
            if REQUIRED_ARGS not in run_line:
                warnings.append(
                    f"workflow run: line has been modified and no longer calls '{REQUIRED_ARGS}'\n"
                    f"  current: {run_line}"
                )

    return warnings


def print_tamper_warnings(warnings):
    """Print tamper warnings loudly so they're impossible to miss in CI logs."""
    print("=" * 60, file=sys.stderr)
    print("  TOKENWATCH — WORKFLOW TAMPER WARNING", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    for w in warnings:
        print(f"\n  {w}", file=sys.stderr)
    print(
        "\n  review .github/workflows/tokenwatch.yml and run "
        "'init --force' to restore it if needed.",
        file=sys.stderr,
    )
    print("=" * 60, file=sys.stderr)
    print(file=sys.stderr)


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------

def run_scan(path, history):
    findings = scan_directory(path)
    if history:
        if is_git_repo(path):
            history_findings = scan_history(path)
            working_tree_keys = {(f["match"], f["label"], f["file"]) for f in findings}
            history_findings = [
                f for f in history_findings
                if (f["match"], f["label"], f["file"]) not in working_tree_keys
            ]
            findings += history_findings
        else:
            print(f"warning: {path} is not a git repository, skipping --history", file=sys.stderr)
    return findings


def print_findings(findings, path):
    if not findings:
        print(f"tokenwatch: scanned {path} — clean, 0 findings")
        return
    print(f"tokenwatch: scanned {path} — {len(findings)} finding(s)\n")
    order = {"high": 0, "medium": 1, "low": 2}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 3)):
        commit_tag = f" [{f['commit']}]" if "commit" in f else ""
        print(f"  {f['severity'].upper():6} {f['file']}:{f['line']}{commit_tag}  {f['label']}  {f['match']}")


def write_report(findings, path):
    scanned     = Path(path).resolve()
    reports_dir = scanned / "reports"
    reports_dir.mkdir(exist_ok=True)
    now          = datetime.now(timezone.utc)
    timestamp    = now.strftime("%Y%m%d_%H%M%S")
    report_path  = reports_dir / f"{scanned.name}_{timestamp}.json"
    report = {
        "tool":          "tokenwatch",
        "version":       "0.1.0",
        "scanned_path":  str(scanned),
        "generated":     now.isoformat(),
        "finding_count": len(findings),
        "findings":      findings,
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\nreport saved to {report_path}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(args):
    repo_root = find_repo_root(Path.cwd())
    tampered  = False

    if repo_root:
        auto_init(repo_root)
        warnings = check_workflow_integrity(repo_root)
        if warnings:
            print_tamper_warnings(warnings)
            tampered = True

    findings = run_scan(args.path, args.history)
    print_findings(findings, args.path)

    # exit 1 if findings OR if the workflow was tampered with —
    # a weakened CI gate is itself a security concern
    return 1 if (findings or tampered) else 0


def cmd_report(args):
    repo_root = find_repo_root(Path.cwd())
    tampered  = False

    if repo_root:
        auto_init(repo_root)
        warnings = check_workflow_integrity(repo_root)
        if warnings:
            print_tamper_warnings(warnings)
            tampered = True

    findings = run_scan(args.path, args.history)
    print_findings(findings, args.path)
    write_report(findings, args.path)
    return 1 if (findings or tampered) else 0


def cmd_init(args):
    repo_root = find_repo_root(Path.cwd())
    if repo_root is None:
        print("error: not inside a git repository — run 'git init' first", file=sys.stderr)
        return 1

    entrypoint  = detect_entrypoint(repo_root)
    wf_path     = workflow_path(repo_root)
    new_content = WORKFLOW_TEMPLATE.format(entrypoint=entrypoint)

    if wf_path.exists():
        if not args.force:
            print(f"error: {wf_path} already exists — use --force to overwrite", file=sys.stderr)
            return 1
        existing_content = wf_path.read_text()
        if existing_content == new_content:
            print(f"tokenwatch: {wf_path} is already up to date, nothing to do")
            return 0
        print(f"tokenwatch: overwriting {wf_path}")
        print(f"  changes:")
        show_diff(existing_content, new_content)
        print()

    generate_workflow(repo_root, entrypoint)
    print(f"tokenwatch: workflow written to {wf_path}")
    print(f"  entrypoint : python {entrypoint} scan . --history")
    print(f"  next steps : git add {wf_path.relative_to(repo_root)}")
    print(f"               git commit -m 'add tokenwatch CI workflow'")
    print(f"               git push")
    return 0


def cmd_verify(args):
    """Run a self-check to confirm tokenwatch is working correctly in this
    environment. Tests both detection layers against known synthetic inputs
    and reports pass/fail for each check.

    Intended to be run once after copying tokenwatch into a new repo.
    Uses only synthetic, non-functional credential strings — nothing real
    is scanned and nothing is written to disk."""
    from scanner_core import scan_text

    CHECKS = [
        # (description, sample_text, expected_label, expected_layer)
        ("AWS Access Key ID detection",
         'key = "AKIAABCDEFGHIJKLMNOP"',
         "AWS Access Key ID", "pattern"),

        ("GitHub PAT detection",
         'token = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"',
         "GitHub Personal Access Token", "pattern"),

        ("Database connection string detection",
         'db = "postgresql://admin:hunter2@db.internal:5432/prod"',
         "Database Connection String", "pattern"),

        ("Entropy-based detection",
         'val = "xK9mQ2pL8vN4wR7tY1zA5bC3dE6fG0hJj2kLm"',
         "High-entropy string", "entropy"),

        ("False positive suppression",
         'normal = "hello_world"',
         None, None),  # should produce zero findings
    ]

    print("tokenwatch — environment verification\n")
    passed = 0
    failed = 0

    for description, sample, expected_label, expected_layer in CHECKS:
        findings = scan_text(sample)

        if expected_label is None:
            # expect clean
            if findings:
                print(f"  FAIL  {description}")
                print(f"        unexpected finding: {findings[0]['label']}")
                failed += 1
            else:
                print(f"  PASS  {description}")
                passed += 1
        else:
            match = next(
                (f for f in findings if f["label"].startswith(expected_label)
                 and f["layer"] == expected_layer),
                None
            )
            if match:
                print(f"  PASS  {description}")
                passed += 1
            else:
                print(f"  FAIL  {description}")
                print(f"        expected [{expected_layer}] '{expected_label}' — not detected")
                failed += 1

    print(f"\n{passed} passed, {failed} failed")

    if failed:
        print(
            "\ntokenwatch may not work correctly in this environment. "
            "Ensure you are running Python 3.9+ and all four files are present.",
            file=sys.stderr,
        )
        return 1

    print("\ntokenwatch is working correctly. run 'scan .' to get started.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="tokenwatch",
        description="Scan a project for accidentally committed secrets.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="scan working tree (optionally + git history)")
    scan_p.add_argument("path", nargs="?", default=".", help="project directory (default: current dir)")
    scan_p.add_argument("--history", action="store_true", help="also scan full git history")
    scan_p.set_defaults(func=cmd_scan)

    report_p = subparsers.add_parser("report", help="scan and export findings to reports/")
    report_p.add_argument("path", nargs="?", default=".", help="project directory (default: current dir)")
    report_p.add_argument("--history", action="store_true", help="also scan full git history")
    report_p.set_defaults(func=cmd_report)

    init_p = subparsers.add_parser("init", help="generate the GitHub Actions workflow file")
    init_p.add_argument("--force", action="store_true", help="overwrite existing workflow file")
    init_p.set_defaults(func=cmd_init)

    verify_p = subparsers.add_parser("verify", help="confirm tokenwatch is working in this environment")
    verify_p.set_defaults(func=cmd_verify)

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()
    exit_code = args.func(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()