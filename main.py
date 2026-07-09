"""
main.py — tokenwatch CLI entrypoint

Commands:
  scan <path> [--history]   scan working tree, optionally + git history
  report <path> [--history] same as scan, but also writes JSON to reports/

Exit code 1 if any findings are present — makes this usable directly as
a CI gate or pre-commit hook without extra wrapper scripts.
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
        run: python {entrypoint} scan . --history
"""


def find_repo_root(start):
    """Walk upward from `start` looking for a .git directory. Returns the
    repo root as a Path, or None if not inside a git repo."""
    current = Path(start).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def cmd_init(args):
    # main.py's own location tells us where tokenwatch lives relative to
    # the repo root — that's what the workflow needs to call.
    script_path = Path(__file__).resolve()
    repo_root = find_repo_root(Path.cwd())

    if repo_root is None:
        print("error: not inside a git repository — run 'git init' first", file=sys.stderr)
        return 1

    try:
        entrypoint = script_path.relative_to(repo_root).as_posix()
    except ValueError:
        # tokenwatch's files live outside the repo entirely — fall back to
        # a sane default and let the user adjust the path themselves.
        entrypoint = "tools/tokenwatch/main.py"
        print(f"warning: could not determine tokenwatch's path inside the repo, "
              f"defaulting to '{entrypoint}' — edit the workflow if that's wrong", file=sys.stderr)

    workflow_dir = repo_root / ".github" / "workflows"
    workflow_path = workflow_dir / "tokenwatch.yml"

    if workflow_path.exists() and not args.force:
        print(f"error: {workflow_path} already exists — use --force to overwrite", file=sys.stderr)
        return 1

    workflow_dir.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(WORKFLOW_TEMPLATE.format(entrypoint=entrypoint))

    print(f"tokenwatch: workflow written to {workflow_path}")
    print(f"  entrypoint set to: python {entrypoint} scan . --history")
    print(f"  commit and push this file to enable tokenwatch on GitHub Actions")
    return 0


def run_scan(path, history):
    findings = scan_directory(path)
    if history:
        if is_git_repo(path):
            history_findings = scan_history(path)
            # Dedup across both scans: history_walker dedupes within history,
            # but a secret still in the working tree will also appear in a
            # past commit. Keep the working-tree hit (no commit tag, more
            # actionable) and drop the history duplicate.
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
    # group by severity, worst first, for a scannable summary
    order = {"high": 0, "medium": 1, "low": 2}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 3)):
        commit_tag = f" [{f['commit']}]" if "commit" in f else ""
        print(f"  {f['severity'].upper():6} {f['file']}:{f['line']}{commit_tag}  {f['label']}  {f['match']}")


def write_report(findings, path):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    project_name = Path(path).resolve().name
    report_path = reports_dir / f"{project_name}_{timestamp}.json"

    report = {
        "tool": "tokenwatch",
        "version": "0.1.0",
        "scanned_path": str(Path(path).resolve()),
        "generated": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": findings,
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\nreport saved to {report_path}")


def cmd_scan(args):
    findings = run_scan(args.path, args.history)
    print_findings(findings, args.path)
    return 1 if findings else 0


def cmd_report(args):
    findings = run_scan(args.path, args.history)
    print_findings(findings, args.path)
    write_report(findings, args.path)
    return 1 if findings else 0


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
    args = parser.parse_args()
    exit_code = args.func(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()