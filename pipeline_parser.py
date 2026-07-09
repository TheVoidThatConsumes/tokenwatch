"""
pipeline_parser.py — workflow file parser for pipewatch

Finds and parses CI/CD pipeline files in a repository, returning a
consistent structure regardless of which CI platform they belong to.

Currently supports:
  - GitHub Actions  (.github/workflows/*.yml / *.yaml)

Planned (not yet implemented):
  - GitLab CI       (.gitlab-ci.yml)
  - Jenkinsfile     (heuristic line matching — Groovy DSL, not a data format)

Each parsed workflow produces a WorkflowFile dataclass containing:
  - path        : relative path inside the repo
  - platform    : "github_actions" | "gitlab_ci" | "jenkinsfile"
  - jobs        : list of Job, each containing steps
  - triggers    : what events fire this workflow
  - raw         : the original parsed YAML/text, for diffing

Each Step contains:
  - id          : step id or generated index label
  - name        : human-readable name if present
  - uses        : action reference if this is a uses: step (e.g. actions/checkout@v4)
  - run         : shell script content if this is a run: step
  - env         : environment variables defined at this step
  - with_inputs : input parameters passed to a uses: action

This is the data contract the rest of pipewatch depends on.
fingerprinter, pin_auditor, and env_checker all consume these structures.
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import yaml


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Step:
    id: str                              # step id or "step_N" if unnamed
    name: Optional[str]                  # human-readable label
    uses: Optional[str]                  # action reference (uses: steps)
    run: Optional[str]                   # shell script (run: steps)
    env: dict                            # env vars defined on this step
    with_inputs: dict                    # inputs passed to a uses: action
    raw: dict                            # original parsed dict, for hashing


@dataclass
class Job:
    id: str                              # job key from the workflow
    name: Optional[str]                  # human-readable job name
    runs_on: Optional[str]               # runner label
    steps: list                          # list of Step
    env: dict                            # env vars defined at job level


@dataclass
class WorkflowFile:
    path: str                            # relative path inside repo
    platform: str                        # "github_actions" etc.
    name: Optional[str]                  # workflow name field
    triggers: list                       # events that fire this workflow
    jobs: list                           # list of Job
    reuses: list                         # reusable workflow references
    raw: dict                            # full parsed YAML


# ---------------------------------------------------------------------------
# GitHub Actions parser
# ---------------------------------------------------------------------------

def _parse_step(raw_step, index):
    """Parse one step dict from a GitHub Actions job into a Step."""
    if not isinstance(raw_step, dict):
        return None

    step_id = str(raw_step.get("id", f"step_{index}"))
    name    = raw_step.get("name")
    uses    = raw_step.get("uses")
    run     = raw_step.get("run")
    env     = raw_step.get("env") or {}
    inputs  = raw_step.get("with") or {}

    # normalise env — YAML sometimes gives us non-string values
    # (e.g. a boolean true or an integer port number)
    env    = {str(k): str(v) for k, v in env.items()}
    inputs = {str(k): str(v) for k, v in inputs.items()}

    return Step(
        id=step_id,
        name=name,
        uses=str(uses) if uses else None,
        run=str(run) if run else None,
        env=env,
        with_inputs=inputs,
        raw=raw_step,
    )


def _parse_job(job_id, raw_job):
    """Parse one job dict from a GitHub Actions workflow into a Job."""
    if not isinstance(raw_job, dict):
        return None

    name     = raw_job.get("name")
    runs_on  = raw_job.get("runs-on")
    raw_env  = raw_job.get("env") or {}
    env      = {str(k): str(v) for k, v in raw_env.items()}

    steps = []
    for i, raw_step in enumerate(raw_job.get("steps") or []):
        step = _parse_step(raw_step, i)
        if step:
            steps.append(step)

    return Job(id=job_id, name=name, runs_on=runs_on, steps=steps, env=env)


def _extract_triggers(on_field):
    """Normalise the `on:` field — it can be a string, list, or dict."""
    if on_field is None:
        return []
    if isinstance(on_field, str):
        return [on_field]
    if isinstance(on_field, list):
        return [str(t) for t in on_field]
    if isinstance(on_field, dict):
        return list(on_field.keys())
    return [str(on_field)]


def _find_reuses(jobs):
    """Find any job-level reusable workflow calls (uses: at job level, not step level).
    These are different from step-level uses: — they call an entire workflow,
    not just an action."""
    reuses = []
    for job in jobs:
        # pipewatch already parsed steps — check the raw job dict for job-level uses:
        pass  # populated from raw_job during parse; placeholder for traversal
    return reuses


def parse_github_actions(path, root):
    """Parse a single GitHub Actions workflow YAML file.
    Returns a WorkflowFile, or None if the file can't be parsed."""
    try:
        text = Path(path).read_text(errors="ignore")
        raw = yaml.safe_load(text)
    except Exception:
        return None

    if not isinstance(raw, dict):
        return None

    name     = raw.get("name")
    # pyyaml treats bare `on:` as the boolean True (YAML reserved word),
    # so check both the string "on" and the boolean True as keys.
    on_field = raw.get("on") or raw.get(True)
    triggers = _extract_triggers(on_field)
    raw_jobs = raw.get("jobs") or {}

    jobs = []
    reuses = []
    for job_id, raw_job in raw_jobs.items():
        if not isinstance(raw_job, dict):
            continue
        # job-level reusable workflow reference
        if "uses" in raw_job:
            reuses.append({
                "job_id": job_id,
                "uses": str(raw_job["uses"]),
                "with": raw_job.get("with") or {},
            })
            continue  # reusable workflow jobs have no steps of their own
        job = _parse_job(job_id, raw_job)
        if job:
            jobs.append(job)

    rel_path = str(Path(path).relative_to(root))
    return WorkflowFile(
        path=rel_path,
        platform="github_actions",
        name=name,
        triggers=triggers,
        jobs=jobs,
        reuses=reuses,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Discovery — find all pipeline files in a repo
# ---------------------------------------------------------------------------

def find_workflow_files(root):
    """Return list of absolute paths to every pipeline file found under root."""
    root = Path(root)
    found = []

    # GitHub Actions
    gha_dir = root / ".github" / "workflows"
    if gha_dir.is_dir():
        for f in gha_dir.iterdir():
            if f.suffix in (".yml", ".yaml") and f.is_file():
                found.append(("github_actions", f))

    # GitLab CI (single file at root)
    gitlab = root / ".gitlab-ci.yml"
    if gitlab.is_file():
        found.append(("gitlab_ci", gitlab))

    # Jenkinsfile (at root or in common locations)
    for candidate in ["Jenkinsfile", "jenkins/Jenkinsfile", "ci/Jenkinsfile"]:
        jf = root / candidate
        if jf.is_file():
            found.append(("jenkinsfile", jf))

    return found


def parse_all(root):
    """Parse every pipeline file in root. Returns list of WorkflowFile objects."""
    root = Path(root)
    workflows = []

    for platform, path in find_workflow_files(root):
        if platform == "github_actions":
            wf = parse_github_actions(path, root)
            if wf:
                workflows.append(wf)
        # gitlab_ci and jenkinsfile parsers: placeholder
        # will be added in a future pass once core functionality is solid

    return workflows


# ---------------------------------------------------------------------------
# Helpers used by other pipewatch modules
# ---------------------------------------------------------------------------

def all_steps(workflows):
    """Flatten all steps across all workflows and jobs into one iterator.
    Yields (workflow_path, job_id, step) tuples."""
    for wf in workflows:
        for job in wf.jobs:
            for step in job.steps:
                yield wf.path, job.id, step


def all_uses_references(workflows):
    """Yield every action reference found across all steps and reusable
    workflow calls. Returns (workflow_path, job_id, step_id, uses_string)."""
    for wf_path, job_id, step in all_steps(workflows):
        if step.uses:
            yield wf_path, job_id, step.id, step.uses
    # also include job-level reusable workflow references
    for wf in workflows:
        for reuse in wf.reuses:
            yield wf.path, reuse["job_id"], "job", reuse["uses"]


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys, json

    root = sys.argv[1] if len(sys.argv) > 1 else "."
    workflows = parse_all(root)

    print(f"found {len(workflows)} workflow file(s) in {root}\n")
    for wf in workflows:
        print(f"  {wf.path}  [{wf.platform}]")
        print(f"    name     : {wf.name}")
        print(f"    triggers : {wf.triggers}")
        print(f"    jobs     : {len(wf.jobs)}")
        for job in wf.jobs:
            print(f"      job '{job.id}' — {len(job.steps)} step(s), runs-on: {job.runs_on}")
            for step in job.steps:
                kind = f"uses: {step.uses}" if step.uses else f"run: {(step.run or '')[:40].strip()}..."
                print(f"        [{step.id}] {step.name or '(unnamed)'}  →  {kind}")
        if wf.reuses:
            print(f"    reusable workflow calls:")
            for r in wf.reuses:
                print(f"      job '{r['job_id']}' calls {r['uses']}")