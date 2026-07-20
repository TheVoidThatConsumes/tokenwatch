"""
scanner_core.py — detection layer for tokenwatch

Two independent signals, combined by the caller:
  1. PATTERNS   — regex signatures for known secret formats
  2. entropy()  — Shannon entropy scoring for high-randomness strings
                  that don't match a known pattern

Kept dependency-free (stdlib `re` + `math` only) so tokenwatch works
as a zero-install, copy-paste-friendly CLI with no external dependencies.
"""

import re
import math
from collections import Counter

# ---------------------------------------------------------------------------
# Layer 1: pattern matching
# ---------------------------------------------------------------------------
# Each entry: (label, compiled regex, severity)
# severity is just a hint for report formatting — not a hard gate.

PATTERNS = [
    ("AWS Access Key ID",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),

    ("AWS Secret Access Key (heuristic)",
     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"), "high"),

    ("GitHub Personal Access Token",
     re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "high"),

    ("GitHub Server-to-Server Token",
     re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "high"),

    ("GitHub OAuth / App Token",
     re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "high"),

    ("Generic Bearer Token",
     re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.=]{20,}"), "medium"),

    ("JWT Structure",
     re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "medium"),

    ("PEM Private Key Header",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"), "high"),

    ("Database Connection String",
     re.compile(r"(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "high"),

    ("Slack Token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "medium"),

    ("Generic API Key Assignment",
     re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token)\b\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), "medium"),

    ("GitLab Runner Registration Token",
     re.compile(r"\bGR1348[0-9A-Za-z_\-]{20}\b"), "high"),
]


def scan_patterns(text):
    """Return list of finding dicts for every pattern match in text."""
    findings = []
    for label, pattern, severity in PATTERNS:
        for m in pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append({
                "label": label,
                "severity": severity,
                "match": _redact(m.group(0)),
                "line": line_no,
                "layer": "pattern",
            })
    return findings


def _redact(s, keep=4):
    """Show just enough of a matched secret to identify it, mask the rest."""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


# ---------------------------------------------------------------------------
# Layer 2: entropy scoring
# ---------------------------------------------------------------------------
# Catches secrets that don't match a known format — e.g. a freshly generated
# API key from some internal service, or a random-looking config value.

ENTROPY_THRESHOLD = 4.5          # bits/char — raised from 4.3 to cut path/hash FPs
MIN_CANDIDATE_LEN = 20           # ignore short strings, too noisy
MAX_CANDIDATE_LEN = 100          # secrets aren't usually huge blobs

# Only consider tokens that look like they could BE a secret:
# long unbroken runs of alnum/symbols, typically inside quotes or after `=`/`:`
CANDIDATE_RE = re.compile(
    r"""['"]([A-Za-z0-9+/=_\-\.]{%d,%d})['"]""" % (MIN_CANDIDATE_LEN, MAX_CANDIDATE_LEN)
)

# Candidates that look like file/module paths are almost never secrets.
# Filter: starts with path prefix OR ends with a recognised file extension.
_PATH_LIKE_RE = re.compile(
    r"""^(?:[./\\])|\.(?:png|jpe?g|gif|svg|js|ts|jsx|tsx|css|vue|html?|woff2?)$""",
    re.IGNORECASE,
)


def shannon_entropy(s):
    """Bits of entropy per character. Higher = more random-looking."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan_entropy(text):
    """Return list of findings for high-entropy quoted strings not already
    caught by a known pattern."""
    findings = []
    for m in CANDIDATE_RE.finditer(text):
        candidate = m.group(1)
        if _PATH_LIKE_RE.search(candidate):
            continue  # file/module path, not a secret
        score = shannon_entropy(candidate)
        if score >= ENTROPY_THRESHOLD:
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append({
                "label": f"High-entropy string (score {score:.2f})",
                "severity": "low",
                "match": _redact(candidate),
                "line": line_no,
                "layer": "entropy",
            })
    return findings


def scan_text(text):
    """Run both layers on a text blob, dedupe overlapping hits."""
    pattern_hits = scan_patterns(text)
    entropy_hits = scan_entropy(text)

    # Dedupe: if a pattern already caught something on this line, don't
    # also report it as a generic entropy hit — pattern match is more
    # specific and entropy would just be noise on top of it.
    pattern_lines = {f["line"] for f in pattern_hits}
    entropy_hits = [f for f in entropy_hits if f["line"] not in pattern_lines]

    return pattern_hits + entropy_hits