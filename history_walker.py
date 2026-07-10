"""
history_walker.py — git history scanner for tokenwatch

Walks every commit in a repo's history and scans the files changed in
that commit for secrets, using `git show <sha>:<path>` to read blob
contents without checking anything out. This catches secrets that were
committed and later removed — deleting a file from HEAD doesn't remove
it from the object database or the log.

Requires `git` on PATH. No network calls — everything is read from the
local .git directory.
"""

import subprocess
from pathlib import Path

from scanner_core import scan_text
from file_walker import load_ignore_patterns, is_ignored, BINARY_EXTENSIONS, MAX_FILE_SIZE_BYTES


def _run_git(args, cwd):
    """Run a git command, return stdout as text. Raises on failure."""
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        errors="ignore",
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def is_git_repo(root):
    try:
        _run_git(["rev-parse", "--is-inside-work-tree"], cwd=root)
        return True
    except RuntimeError:
        return False


def list_commits(root):
    """Return list of commit SHAs, oldest first."""
    out = _run_git(["log", "--pretty=format:%H", "--reverse"], cwd=root)
    return [line.strip() for line in out.splitlines() if line.strip()]


def files_changed_in_commit(root, sha):
    """Return list of file paths added/modified in a commit (skip deletions —
    nothing to scan in a file that no longer exists at that revision)."""
    out = _run_git(
        ["diff-tree", "--no-commit-id", "--name-status", "-r", sha],
        cwd=root,
    )
    changed = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            status, path = parts
            if not status.startswith("D"):  # skip deletions, nothing to read
                changed.append(path)
        elif len(parts) == 3:
            # rename: "R<score>\t<old_path>\t<new_path>"
            # scan the new path — that's what exists at this commit
            status, _old_path, new_path = parts
            if status.startswith("R"):
                changed.append(new_path)
        # anything else (malformed) — skip silently
    return changed


def read_blob(root, sha, path):
    """Read a file's content as it existed at a specific commit."""
    try:
        return _run_git(["show", f"{sha}:{path}"], cwd=root)
    except RuntimeError:
        return None  # e.g. path didn't exist at that rev (renames etc.)


def scan_history(root):
    """Scan every commit's changed files for secrets.

    Returns findings tagged with commit sha + file path, so a report can
    show not just *what* leaked but *when* — which matters for deciding
    whether a credential needs rotating (if it only ever hit a local
    branch that was never pushed, urgency is lower than if it's sitting
    on origin/main).
    """
    root = Path(root)
    if not is_git_repo(root):
        raise RuntimeError(f"{root} is not a git repository")

    ignore_patterns = load_ignore_patterns(root)
    all_findings = []
    seen_secrets = set()  # (match, label, path) — avoid reporting the
                           # same secret in every single commit that touched
                           # the file it lives in; report first occurrence only

    for sha in list_commits(root):
        for path in files_changed_in_commit(root, sha):
            fpath = Path(path)

            if fpath.suffix.lower() in BINARY_EXTENSIONS:
                continue
            if is_ignored(fpath, ignore_patterns):
                continue

            content = read_blob(root, sha, path)
            if content is None:
                continue
            if len(content.encode("utf-8", errors="ignore")) > MAX_FILE_SIZE_BYTES:
                continue

            findings = scan_text(content)
            for f in findings:
                dedup_key = (f["match"], f["label"], path)
                if dedup_key in seen_secrets:
                    continue
                seen_secrets.add(dedup_key)

                f["file"] = path
                f["commit"] = sha[:10]  # short sha, readable in a report
                all_findings.append(f)

    return all_findings


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = scan_history(target)

    print(f"scanned git history in {target} — {len(results)} finding(s)")
    for f in results:
        print(f"  [{f['commit']}] {f['file']}:{f['line']}  [{f['severity']}] {f['label']}  {f['match']}")