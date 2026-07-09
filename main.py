"""
main.py — tokenwatch CLI entrypoint

Commands:
  scan <path> [--history]   scan working tree, optionally + git history
  report <path> [--history] same as scan, but also writes JSON to reports/
  init [--force]            generate the GitHub Actions workflow file

Exit code 1 if any findings are present — makes this usable directly as
a CI gate or pre-commit hook without extra wrapper scripts.

On first run, scan automatically generates the GitHub Actions workflow
if one doesn't already exist — no need to run init manually.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from file_walker import scan_directory
from history_walker import scan_history, is_git_repo


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
    """Return the path to main.py relative to repo_root as a posix string.
    Falls back to a sensible default with a warning if detection fails."""
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
# Workflow generation — shared between auto-init and cmd_init
# ---------------------------------------------------------------------------

def workflow_path(repo_root):
    return repo_root / ".github" / "workflows" / "tokenwatch.yml"


def generate_workflow(repo_root, entrypoint):
    """Write the workflow file. Returns the path it was written to."""
    wf_path = workflow_path(repo_root)
    wf_path.parent.mkdir(parents=True, exist_ok=True)
    wf_path.write_text(WORKFLOW_TEMPLATE.format(entrypoint=entrypoint))
    return wf_path


def show_diff(existing_text, new_text):
    """Print a simple line-level diff between existing and new workflow content."""
    existing_lines = set(existing_text.splitlines())
    new_lines      = set(new_text.splitlines())

    removed = existing_lines - new_lines
    added   = new_lines - existing_lines

    if not removed and not added:
        print("  (no content changes)")
        return

    for line in sorted(removed):
        print(f"  - {line}")
    for line in sorted(added):
        print(f"  + {line}")


def auto_init(repo_root):
    """Called automatically by scan/report on first run if no workflow exists.
    Silent if the workflow already exists — only acts when there's nothing there."""
    wf_path = workflow_path(repo_root)
    if wf_path.exists():
        return  # already installed, nothing to do

    entrypoint = detect_entrypoint(repo_root)
    generate_workflow(repo_root, entrypoint)

    print(f"tokenwatch: no workflow found — generated {wf_path}")
    print(f"  run: git add {wf_path.relative_to(repo_root)}")
    print(f"       git commit -m 'add tokenwatch CI workflow'")
    print(f"       git push")
    print()


# ---------------------------------------------------------------------------
# Scan logic
# ---------------------------------------------------------------------------

def run_scan(path, history):
    findings = scan_directory(path)
    if history:
        if is_git_repo(path):
            history_findings = scan_history(path)
            # Dedup: keep working-tree hit (no commit tag, more actionable)
            # and drop the history duplicate for the same secret in the same file.
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
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    timestamp    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    project_name = Path(path).resolve().name
    report_path  = reports_dir / f"{project_name}_{timestamp}.json"

    report = {
        "tool":          "tokenwatch",
        "version":       "0.1.0",
        "scanned_path":  str(Path(path).resolve()),
        "generated":     datetime.now(timezone.utc).isoformat(),
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
    if repo_root:
        auto_init(repo_root)  # no-op if workflow already exists

    findings = run_scan(args.path, args.history)
    print_findings(findings, args.path)
    return 1 if findings else 0


def cmd_report(args):
    repo_root = find_repo_root(Path.cwd())
    if repo_root:
        auto_init(repo_root)

    findings = run_scan(args.path, args.history)
    print_findings(findings, args.path)
    write_report(findings, args.path)
    return 1 if findings else 0


def cmd_init(args):
    repo_root = find_repo_root(Path.cwd())
    if repo_root is None:
        print("error: not inside a git repository — run 'git init' first", file=sys.stderr)
        return 1

    entrypoint = detect_entrypoint(repo_root)
    wf_path    = workflow_path(repo_root)
    new_content = WORKFLOW_TEMPLATE.format(entrypoint=entrypoint)

    if wf_path.exists():
        if not args.force:
            print(f"error: {wf_path} already exists — use --force to overwrite", file=sys.stderr)
            return 1
        # --force: show a diff of what's changing before overwriting
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

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()
    exit_code = args.func(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()