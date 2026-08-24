#!/usr/bin/env python3
"""Decide which review passes must run, from evidence rather than from phrasing.

A pass may be skipped only when all four hold:

  1. its inputs are byte-identical to the last recorded run;
  2. the pass version is unchanged (the *method* did not improve);
  3. the recorded capability watermark covers the current one; and
  4. it is not past its decay horizon.

Condition 2 is the one that is usually missing. "Passed" is a property of
(artifact x method), not of the artifact: a figure whose bytes never changed can
still be wrong under a method that renders it in both themes when the previous
method rendered one. Bumping a pass version reopens every cached verdict for it.

Condition 3 never blocks a review. A weaker current capability skips the passes a
stronger run already covered and reports them as resting on that run; it never
exits and never refuses. See `capability_covers`.

Dependency-free; operates on git state and reviews/REVIEW_STATE.json in whatever
repository it runs in.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

STATE_PATH = Path("reviews/REVIEW_STATE.json")
SCHEMA_VERSION = 1

# --------------------------------------------------------------------------
# Capability watermark
#
# Deliberately a PARTIAL order. An unknown model is incomparable, not weak, so a
# model this table has never heard of forces a re-run rather than silently
# inheriting a cached verdict. That errs toward redundant work instead of toward
# false assurance, and it means the table going stale is safe.
# --------------------------------------------------------------------------
MODEL_RANK = {
    "claude-haiku-4-5": 1,
    "claude-sonnet-5": 2,
    "claude-fable-5": 2,
    "claude-opus-5": 3,
}
EFFORT_RANK = {"low": 1, "medium": 2, "high": 3, "xhigh": 4, "max": 5}


def capability_covers(recorded, current):
    """True when `recorded` was at least as capable as `current` on both axes.

    Used to SKIP work, never to refuse it. Any unknown value returns False, so
    the pass runs.
    """
    r_model = MODEL_RANK.get((recorded or {}).get("model"))
    c_model = MODEL_RANK.get((current or {}).get("model"))
    r_effort = EFFORT_RANK.get((recorded or {}).get("effort"))
    c_effort = EFFORT_RANK.get((current or {}).get("effort"))
    if None in (r_model, c_model, r_effort, c_effort):
        return False
    return r_model >= c_model and r_effort >= c_effort


# --------------------------------------------------------------------------
# Input classes
# --------------------------------------------------------------------------
CLASS_GLOBS = {
    "prose": ["*.md", "*.markdown", "*.html", "*.htm", "*.rst", "*.adoc", "*.txt"],
    "visual": ["*.svg", "*.png", "*.jpg", "*.jpeg", "*.webp", "*.gif", "*.pdf", "*.mmd"],
    "code": ["*.py", "*.js", "*.mjs", "*.cjs", "*.ts", "*.tsx", "*.go", "*.rs", "*.rb", "*.sh"],
    "style": ["*.css", "*.scss", "*.sass", "*.less"],
    "metadata": ["package.json", "*.yml", "*.yaml", "*.toml", "*.cfg", "*.ini"],
    "register": ["reviews/CONTENT_DECISIONS.yml"],
}

# The review apparatus is not reviewed content. Excluding it matters for two
# reasons: the review's own output would otherwise invalidate every pass on the
# next run (a fingerprint that changes because it was written down), and syncing
# a newer template or script from the skill would falsely reopen content passes
# that no content change justifies.
EXCLUDED = [
    "reviews/REVIEW_STATE.json",
    "reviews/LATEST_REVIEW.md",
    "reviews/REVIEW_TEMPLATE.md",
    "reviews/CONTENT_DECISION_GUIDE.md",
    "scripts/review_passes.py",
    "scripts/capture_review_state.py",
    "scripts/verify_content_decisions.py",
    "node_modules/*",
    ".git/*",
]

# The decision register is the sole input of `decision-reconciliation`. Without
# this it would also match the `metadata` glob `*.yml`, so recording a decision
# would reopen cross-format and cross-page for no content reason.
CLASS_EXCLUSIVE = {"reviews/CONTENT_DECISIONS.yml": "register"}

URL_RE = re.compile(rb"https?://[^\s\"'<>)\]}]+")


# --------------------------------------------------------------------------
# Pass registry
#
# `version` is the method version. Bump it whenever this skill changes WHAT the
# pass requires — not when content changes. Every bump reopens that pass for all
# content, which is the mechanism that catches a method that was previously too
# shallow. Record why in `changelog`.
#
# `decay_days` applies only to passes whose conclusions an external world can
# invalidate with no local file changing: a link rots, a standard is revised, an
# attack is published. Passes determined entirely by the content itself never
# decay, because nothing outside the repository can falsify them.
# --------------------------------------------------------------------------
PASSES = {
    "factual-correctness": {
        "title": "Factual and technical correctness",
        "version": 1,
        "inputs": ["prose", "code"],
        "decay_days": 180,
        "changelog": {1: "Initial versioned definition."},
    },
    "evidence-authority": {
        "title": "Evidence, authority, version, date, jurisdiction, applicability",
        "version": 1,
        # Fingerprinted on the URL SET, not the prose bytes: editing a paragraph
        # must not force a re-fetch of citations that did not change.
        "inputs": ["citations"],
        "decay_days": 90,
        "changelog": {1: "Initial versioned definition."},
    },
    "adversarial-claims": {
        "title": "Adversarial wording, assumptions, attacker state, counterexamples",
        "version": 1,
        "inputs": ["prose"],
        "decay_days": None,
        "changelog": {1: "Initial versioned definition."},
    },
    "terminology-taxonomy": {
        "title": "Terminology, taxonomy, conceptual boundaries",
        "version": 1,
        "inputs": ["prose"],
        "decay_days": None,
        "changelog": {1: "Initial versioned definition."},
    },
    "cross-format": {
        "title": "Cross-format consistency",
        "version": 1,
        "inputs": ["prose", "visual", "code", "metadata"],
        "decay_days": None,
        "changelog": {1: "Initial versioned definition."},
    },
    "visual-content": {
        "title": "Visual content, independently of the prose",
        "version": 2,
        "inputs": ["visual", "style", "code"],
        "decay_days": None,
        "changelog": {
            1: "Render each visual standalone; check correctness, self-sufficiency, provenance.",
            2: "Render in BOTH light and dark themes, and at a mobile width. v1 rendered a "
               "single theme at desktop width and passed figures whose theme-dependent fills "
               "resolved to an unreadable value in the other theme, and whose text scaled below "
               "legibility on a narrow viewport. Bytes were identical; the method was deficient.",
        },
    },
    "cross-page": {
        "title": "Cross-page consistency, prerequisites, sequence, duplication",
        "version": 1,
        "inputs": ["prose", "metadata"],
        "decay_days": None,
        "changelog": {1: "Initial versioned definition."},
    },
    "topic-completeness": {
        "title": "Topic completeness",
        "version": 1,
        "inputs": ["prose"],
        "decay_days": 180,
        "changelog": {1: "Initial versioned definition."},
    },
    "argument-integrity": {
        "title": "Argument integrity (thesis, comparison set, demonstration, dangling claims)",
        "version": 1,
        "inputs": ["prose"],
        "decay_days": None,
        "changelog": {1: "Initial versioned definition."},
    },
    "executable-demonstration": {
        "title": "Executable demonstration correctness",
        "version": 2,
        "inputs": ["code", "prose"],
        "decay_days": None,
        "changelog": {
            1: "Run each demonstration and confirm it produces the claimed result.",
            2: "Drive each demonstration with ADVERSARIAL inputs, not defaults, and confirm "
               "every reported outcome is derived from the observed result rather than asserted. "
               "v1 ran default inputs and passed demonstrations that announced success on inputs "
               "where they had not produced it.",
        },
    },
    "decision-reconciliation": {
        "title": "Durable content-decision reconciliation",
        "version": 1,
        "inputs": ["register"],
        "decay_days": None,
        "changelog": {1: "Initial versioned definition."},
    },
}

# Cheap, deterministic, model-independent. Never cached, never skipped: these are
# where findings go to become permanent, and they cost close to nothing.
ALWAYS_RUN = {
    "mechanical-validation": "Link, syntax, generator-correspondence, test, lint and guard checks",
    "guard-regression": "Every guard derived from a previous finding still fires",
    "residual-exhaustion": "Reread each unit touched by a finding (only when a pass produced one)",
}


def git(root, *args):
    result = subprocess.run(
        ["git", *args], cwd=root, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.rstrip("\n")


def repository_root():
    here = Path(__file__).resolve().parent
    out = subprocess.run(
        ["git", "-C", str(here), "rev-parse", "--show-toplevel"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return Path(out.stdout.strip()).resolve()


def repository_files(root):
    names = git(root, "ls-files", "--cached", "--others", "--exclude-standard")
    out = []
    for name in names.splitlines():
        if not name:
            continue
        if any(fnmatch.fnmatch(name, pattern) for pattern in EXCLUDED):
            continue
        path = root / name
        if path.is_file():
            out.append((name, path))
    return sorted(out)


def files_in_class(files, class_name):
    globs = CLASS_GLOBS[class_name]
    out = []
    for name, path in files:
        owner = CLASS_EXCLUSIVE.get(name)
        if owner is not None and owner != class_name:
            continue
        if any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(Path(name).name, g) for g in globs):
            out.append((name, path))
    return out


def class_fingerprint(files, class_name):
    """Fingerprint one input class.

    `citations` is content-derived rather than file-derived: the URL set, sorted
    and deduplicated. Editing prose around a citation must not invalidate the
    citation check, and adding one must.
    """
    digest = hashlib.sha256()
    if class_name == "citations":
        urls = set()
        for _, path in files_in_class(files, "prose"):
            try:
                urls.update(m.group(0).decode("utf-8", "replace")
                            for m in URL_RE.finditer(path.read_bytes()))
            except OSError:
                continue
        for url in sorted(urls):
            digest.update(url.encode("utf-8"))
            digest.update(b"\0")
        return digest.hexdigest(), len(urls)

    members = files_in_class(files, class_name)
    for name, path in members:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError:
            digest.update(b"<unreadable>")
        digest.update(b"\0")
    return digest.hexdigest(), len(members)


def pass_fingerprint(files, spec):
    digest = hashlib.sha256()
    counts = {}
    for class_name in spec["inputs"]:
        fingerprint, count = class_fingerprint(files, class_name)
        counts[class_name] = count
        digest.update(class_name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(fingerprint.encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest(), counts


def load_state(root):
    path = root / STATE_PATH
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{STATE_PATH} exists but is unreadable: {error}") from error


def days_since(iso_date, today):
    try:
        then = dt.date.fromisoformat(iso_date)
    except (TypeError, ValueError):
        return None
    return (today - then).days


def plan(root, current, today):
    files = repository_files(root)
    state = load_state(root)
    recorded_passes = (state or {}).get("passes", {})

    decisions = []
    for pass_id, spec in sorted(PASSES.items()):
        fingerprint, counts = pass_fingerprint(files, spec)
        prior = recorded_passes.get(pass_id)

        if prior is None:
            reasons = ["no recorded run for this pass"]
        else:
            reasons = []
            if prior.get("version") != spec["version"]:
                prior_v = prior.get("version")
                note = spec["changelog"].get(spec["version"], "")
                reasons.append(
                    f"method version changed v{prior_v} -> v{spec['version']}"
                    + (f": {note}" if note else "")
                )
            if prior.get("input_fingerprint_sha256") != fingerprint:
                reasons.append("inputs changed since the recorded run")
            if not capability_covers(prior, current):
                reasons.append(
                    f"recorded capability ({prior.get('model')}/{prior.get('effort')}) "
                    f"does not cover current ({current.get('model')}/{current.get('effort')})"
                )
            if spec["decay_days"] is not None:
                age = days_since(prior.get("verified_on"), today)
                if age is None:
                    reasons.append("recorded verification date is missing or unparseable")
                elif age > spec["decay_days"]:
                    reasons.append(
                        f"decay horizon passed ({age}d since verification, "
                        f"limit {spec['decay_days']}d — externally invalidatable)"
                    )

        decisions.append({
            "pass": pass_id,
            "title": spec["title"],
            "version": spec["version"],
            "run": bool(reasons),
            "reasons": reasons or ["inputs, method, capability and freshness all unchanged"],
            "input_fingerprint_sha256": fingerprint,
            "input_counts": counts,
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "evaluated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository": str(root),
        "commit": git(root, "rev-parse", "HEAD"),
        "branch": git(root, "branch", "--show-current") or "DETACHED",
        "worktree": "dirty" if git(root, "status", "--porcelain=v1") else "clean",
        "current_capability": current,
        "prior_review": (state or {}).get("last_review"),
        "has_prior_state": state is not None,
        "always_run": ALWAYS_RUN,
        "passes_to_run": [d["pass"] for d in decisions if d["run"]],
        "passes_cached": [d["pass"] for d in decisions if not d["run"]],
        "decisions": decisions,
    }


def record(root, current, today, verdicts):
    files = repository_files(root)
    state = load_state(root) or {"schema_version": SCHEMA_VERSION, "passes": {}}
    state["schema_version"] = SCHEMA_VERSION
    state["last_review"] = {
        "date": today.isoformat(),
        "commit": git(root, "rev-parse", "HEAD"),
        "branch": git(root, "branch", "--show-current") or "DETACHED",
        "model": current.get("model"),
        "effort": current.get("effort"),
    }
    passes = state.setdefault("passes", {})
    for pass_id, spec in PASSES.items():
        if pass_id not in verdicts:
            continue  # pass was cached this run; leave its earlier record intact
        fingerprint, _ = pass_fingerprint(files, spec)
        passes[pass_id] = {
            "version": spec["version"],
            "input_fingerprint_sha256": fingerprint,
            "model": current.get("model"),
            "effort": current.get("effort"),
            "verified_on": today.isoformat(),
            "verdict": verdicts[pass_id],
        }
    path = root / STATE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return state


def render_plan_text(result):
    lines = []
    prior = result["prior_review"]
    if not result["has_prior_state"]:
        lines.append("No prior review state — every pass runs (first review under pass versioning).")
    else:
        lines.append(
            f"Prior review: {prior.get('date')} at {prior.get('model')}/{prior.get('effort')} "
            f"(commit {str(prior.get('commit'))[:8]})"
        )
    cur = result["current_capability"]
    lines.append(f"This review:  {cur.get('model')}/{cur.get('effort')} on {result['branch']} "
                 f"({result['commit'][:8]}, {result['worktree']})")
    lines.append("")
    lines.append(f"RUN ({len(result['passes_to_run'])}):")
    for decision in result["decisions"]:
        if decision["run"]:
            lines.append(f"  - {decision['pass']} (v{decision['version']})")
            for reason in decision["reasons"]:
                lines.append(f"      {reason}")
    lines.append("")
    lines.append(f"CACHED ({len(result['passes_cached'])}) — state carried forward, not re-derived:")
    for decision in result["decisions"]:
        if not decision["run"]:
            lines.append(f"  - {decision['pass']} (v{decision['version']})")
    lines.append("")
    lines.append("ALWAYS RUN — cheap, deterministic, never cached:")
    for name, description in sorted(result["always_run"].items()):
        lines.append(f"  - {name}: {description}")
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", required=True, help="Model id running this review, e.g. claude-opus-5")
    parser.add_argument("--effort", required=True, choices=sorted(EFFORT_RANK),
                        help="Reasoning effort for this review")
    parser.add_argument("--record", metavar="JSON",
                        help='Write results instead of planning: \'{"visual-content":"clean",...}\' '
                             "mapping pass id to clean|findings. Only passes named here are updated. "
                             "The verdict records what that run FOUND, not what is still open: it is "
                             "written after remediation, so its fingerprint describes the fixed "
                             "content. Routing never reads it; anything deliberately left unfixed "
                             "belongs in reviews/CONTENT_DECISIONS.yml as a rejected or "
                             "accepted-limitation record.")
    parser.add_argument("--today", help="Override today's date (YYYY-MM-DD), for testing")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args()


def main():
    args = parse_args()
    current = {"model": args.model, "effort": args.effort}
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    try:
        root = repository_root()
        if args.record:
            verdicts = json.loads(args.record)
            unknown = sorted(set(verdicts) - set(PASSES))
            if unknown:
                raise ValueError(f"unknown pass ids: {', '.join(unknown)}")
            bad = {k: v for k, v in verdicts.items() if v not in ("clean", "findings")}
            if bad:
                raise ValueError(f"verdicts must be 'clean' or 'findings': {bad}")
            state = record(root, current, today, verdicts)
            print(f"recorded {len(verdicts)} pass result(s) to {STATE_PATH}")
            if args.json:
                print(json.dumps(state, indent=2, sort_keys=True))
            return 0
        result = plan(root, current, today)
        print(json.dumps(result, indent=2, sort_keys=True) if args.json else render_plan_text(result))
        return 0
    except (subprocess.CalledProcessError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"review-pass planning failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
