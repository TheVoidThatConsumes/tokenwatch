"""
file_walker.py — directory scanner for tokenwatch

Walks a project directory, skips things that would just be noise
(binary files, .git internals, node_modules, venvs), applies
.tokenwatchignore, and feeds each readable text file into scanner_core.

Kept separate from scanner_core so the detection logic and the
"what files do we even look at" logic can be tested independently.
"""

import os
import fnmatch
from pathlib import Path

from scanner_core import scan_text

# Directories we never walk into — pure noise, huge, or binary-heavy
DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    "vendor", "target",  # rust/go build output
    "reports",  # tokenwatch report output — skip self-scan
}

# Extensions we skip outright — binary formats where a "secret-looking
# string" is almost certainly just compressed/encoded noise, not a real leak
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".exe", ".dll", ".so", ".dylib", ".woff", ".woff2", ".ttf",
    ".mp4", ".mp3", ".wav", ".bin", ".pyc", ".class", ".jar",
    ".db", ".sqlite", ".sqlite3",  # database files
}

MINIFIED_NAME_PATTERNS = {".min.", ".bundle.", ".chunk.", ".dev.", ".prod."}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB — skip huge files, likely not source


# Files we never scan — tokenwatch's own generated files
DEFAULT_EXCLUDE_FILES = {
    ".tokenwatch_state",   # our state file — contains hashes, not secrets
    ".tokenwatchignore",   # our ignore file
    "package-lock.json",   # npm integrity hashes — not secrets
    "yarn.lock",           # yarn integrity hashes
    "poetry.lock",         # poetry integrity hashes
    "Pipfile.lock",        # pipenv integrity hashes
}



def is_minified(fname):
    """True for machine-generated JS/CSS bundles (*.min.js, *.bundle.dev.js, etc.)."""
    lower = fname.lower()
    return any(p in lower for p in MINIFIED_NAME_PATTERNS)


def is_binary_content(fpath):
    """Sniff the first 8 KB for null bytes — reliable binary detector for
    extensionless files (e.g. build cache blobs, compiled assets)."""
    try:
        return b"\x00" in fpath.read_bytes()[:8192]
    except OSError:
        return False


def load_ignore_patterns(root):
    """Read .tokenwatchignore from project root, if present.
    One glob pattern per line, '#' comments allowed, blank lines skipped.
    Patterns are matched against the path relative to root."""
    ignore_path = Path(root) / ".tokenwatchignore"
    patterns = []
    if ignore_path.exists():
        for line in ignore_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_ignored(rel_path, patterns):
    """Check a relative path against .tokenwatchignore glob patterns.
    Matches both the full relative path and just the filename, so a
    pattern like 'test_fixtures/*' or '*.example' both work as expected."""
    rel_str = str(rel_path).replace(os.sep, "/")
    name = Path(rel_path).name
    for pattern in patterns:
        if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(name, pattern):
            return True
    return False


def iter_scannable_files(root):
    """Yield Path objects for every file worth scanning under root."""
    root = Path(root)
    ignore_patterns = load_ignore_patterns(root)

    for dirpath, dirnames, filenames in os.walk(root):
        # prune excluded directories in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS]

        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel = fpath.relative_to(root)

            if fpath.suffix.lower() in BINARY_EXTENSIONS:
                continue
            if is_minified(fname):
                continue
            if fname in DEFAULT_EXCLUDE_FILES:
                continue
            if is_ignored(rel, ignore_patterns):
                continue
            try:
                if fpath.stat().st_size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue  # broken symlink etc.
            if is_binary_content(fpath):
                continue

            yield fpath


def scan_directory(root):
    """Walk root, scan every eligible file, return list of findings with
    file paths attached (scanner_core findings only carry line numbers)."""
    root = Path(root)
    all_findings = []

    for fpath in iter_scannable_files(root):
        try:
            text = fpath.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        findings = scan_text(text)
        for f in findings:
            f["file"] = str(fpath.relative_to(root))
        all_findings.extend(findings)

    return all_findings


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    results = scan_directory(target)

    print(f"scanned {target} — {len(results)} finding(s)")
    for f in results:
        print(f"  {f['file']}:{f['line']}  [{f['severity']}] {f['label']}  {f['match']}")