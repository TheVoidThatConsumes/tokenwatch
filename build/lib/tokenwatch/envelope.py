"""
envelope.py — converts tokenwatch's internal finding dicts into the shared
Gossamer finding-envelope schema (schema/finding-envelope.schema.json).

Internal finding shape (from scanner_core.py / history_walker.py):
    {"label": str, "severity": "high"|"medium"|"low", "file": str,
     "line": int, "match": str, "layer": "pattern"|"entropy",
     "commit": str (optional, history findings only)}

Envelope finding shape (required by schema):
    {"id": str, "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO",
     "category": str, "title": str, "description": str (optional),
     "location": str, "evidence": str (optional)}
"""

from datetime import datetime, timezone
from pathlib import Path

try:
    from tokenwatch import __version__
except ImportError:
    __version__ = "unknown"

SCHEMA_VERSION = "1.0"
CATEGORY = "secret-exposure"  # only category tokenwatch owns, per categories.json

# severity is lowercase internally ("high"/"medium"/"low"); tokenwatch never
# emits CRITICAL or INFO today, so those two are mapped defensively only.
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

# label (from scanner_core.PATTERNS) -> id subtype code. Order matters only
# for the startswith fallback at the bottom of label_to_subtype().
LABEL_SUBTYPES = [
    ("AWS Access Key ID", "AWS"),
    ("AWS Secret Access Key", "AWS"),
    ("GitHub Personal Access Token", "GITHUB"),
    ("GitHub Server-to-Server Token", "GITHUB"),
    ("GitHub OAuth", "GITHUB"),
    ("Generic Bearer Token", "BEARER"),
    ("JWT Structure", "JWT"),
    ("PEM Private Key Header", "PRIVATEKEY"),
    ("Database Connection String", "DBCONN"),
    ("Slack Token", "SLACK"),
    ("Generic API Key Assignment", "GENERICKEY"),
    ("GitLab Runner Registration Token", "GITLAB"),
    ("High-entropy string", "ENTROPY"),
    ("Shallow clone", "SHALLOW"),
]


def label_to_subtype(label):
    for prefix, subtype in LABEL_SUBTYPES:
        if label.startswith(prefix):
            return subtype
    return "GENERIC"  # unrecognized label — still schema-valid, just unspecific


def _location(f):
    """<path>:<line> for working-tree findings, <commit>:<path>:<line> for
    history findings. Opaque per the schema — never parsed by consumers."""
    if "commit" in f:
        return f"{f['commit']}:{f['file']}:{f['line']}"
    return f"{f['file']}:{f['line']}"


def to_envelope_finding(f, subtype_counters):
    subtype = label_to_subtype(f["label"])
    subtype_counters[subtype] = subtype_counters.get(subtype, 0) + 1
    finding_id = f"TW-{subtype}-{subtype_counters[subtype]:03d}"

    severity = SEVERITY_MAP.get(f.get("severity", "").lower(), "MEDIUM")
    category = f.get("category", CATEGORY)  # findings may override the
                                             # default (e.g. scan-coverage-gap)

    evidence_bits = []
    if f.get("layer") and f["layer"] != "coverage":
        evidence_bits.append(f"{f['layer']} match")
    if "commit" in f:
        evidence_bits.append(f"found in commit {f['commit']}")
    evidence = "; ".join(evidence_bits) or None

    description = f.get("description") or f"{f['label']} detected via {f.get('layer', 'pattern')} matching."

    envelope_finding = {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": f["label"],
        "description": description,
        "location": _location(f),
    }
    if evidence:
        envelope_finding["evidence"] = evidence
    return envelope_finding


def build_envelope(findings, repo, baseline_commit=None):
    """Convert a list of tokenwatch's internal finding dicts into a full
    finding-envelope.schema.json-conformant report dict."""
    subtype_counters = {}
    # stable order: severity rank, then file, then line — keeps id numbering
    # deterministic across runs on unchanged input, which matters for diffing.
    rank = {"high": 0, "medium": 1, "low": 2, "critical": -1, "info": 3}
    ordered = sorted(
        findings,
        key=lambda f: (rank.get(f.get("severity", "").lower(), 4), f.get("file", ""), f.get("line", 0)),
    )

    envelope_findings = [to_envelope_finding(f, subtype_counters) for f in ordered]

    summary = {"total": len(envelope_findings), "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for ef in envelope_findings:
        summary[ef["severity"]] += 1

    envelope = {
        "schema_version": SCHEMA_VERSION,
        "tool": "tokenwatch",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": str(Path(repo).resolve()),
        "findings": envelope_findings,
        "summary": summary,
    }
    if baseline_commit:
        envelope["baseline_commit"] = baseline_commit
    return envelope