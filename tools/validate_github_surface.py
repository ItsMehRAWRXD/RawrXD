"""GitHub-surface validator for RawrXD.

Read-only, offline validation of the repo's GitHub Actions surface, covering the
failure classes that have historically broken this repo's CI:

  1. Workflow YAML validity  - parse every .github/workflows/*.yml, require
                               name/on(True)/jobs, runs-on, valid shell names.
  2. Referenced paths        - every script/file a workflow invokes must exist
                               at the path the workflow uses, relative to the
                               checkout root (both / and \\ separators).
  3. Committed conflicts     - files tracked at a ref that still contain
                               unresolved merge-conflict blocks (a committed
                               conflict in a workflow file makes every run a
                               0-job startup failure).
  4. Non-UTF-8 BOMs          - tracked text files whose raw blob starts with a
                               non-UTF-8 BOM (e.g. UTF-16) - cmake/git tooling
                               rejects these at configure time.

Usage:
  python tools/validate_github_surface.py [--ref REF] [--live]

  --ref REF   git ref to validate (default: HEAD)
  --live      also query the GitHub API for the registered workflow set and
              the most recent run conclusions (requires authenticated gh CLI)

Exit code is 1 if any P0/P1 problem is found, 0 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF_DIR = os.path.join(REPO_ROOT, ".github", "workflows")

VALID_SHELLS = {"bash", "pwsh", "sh", "cmd", "powershell", "python"}

# A referenced file path in a run/with block: word chars, separators, extension.
PATH_TOKEN = re.compile(
    r"[\w.@-]+(?:[\\/][\w.@-]+)+\.(?:ps1|py|bat|cmd|asm|inc|c|h|hpp|cpp|json|md|yml|yaml|txt)\b"
)

CONFLICT_OPEN = re.compile(rb"^<{7}(?!<)")
CONFLICT_SEP = re.compile(rb"^={7}\s*$")
CONFLICT_CLOSE = re.compile(rb"^>{7}(?!>)")

P0, P1, P2 = "P0", "P1", "P2"
findings: list[tuple[str, str]] = []


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", REPO_ROOT, *args], capture_output=True
    ).stdout


def add(sev: str, msg: str) -> None:
    findings.append((sev, msg))


# ---------------------------------------------------------------------------
# 1+2. Workflow YAML and referenced paths
# ---------------------------------------------------------------------------
def validate_workflow(ref: str) -> None:
    import yaml

    if ref == "HEAD":
        names = [
            f
            for f in sorted(os.listdir(WF_DIR))
            if os.path.isfile(os.path.join(WF_DIR, f))
            and f.endswith((".yml", ".yaml"))
        ]
        read = lambda name: open(  # noqa: E731
            os.path.join(WF_DIR, name), "rb"
        ).read()
    else:
        listing = git("ls-tree", "-r", "--name-only", ref).decode("utf-8", "replace")
        names = [
            p[len(".github/workflows/") :]
            for p in listing.splitlines()
            if p.startswith(".github/workflows/")
            and p.endswith((".yml", ".yaml"))
        ]
        read = lambda name: git("cat-file", "blob", f"{ref}:.github/workflows/{name}")

    if not names:
        add(P0, f"{ref}: no workflow files found under .github/workflows/")
        return

    # Path existence must be resolved inside the ref's tree, not the working
    # tree (the working tree may be a different branch with a different layout).
    if ref == "HEAD":

        def exists(p: str) -> bool:
            return os.path.exists(os.path.join(REPO_ROOT, p.replace("\\", "/")))

    else:

        def exists(p: str) -> bool:
            return (
                subprocess.run(
                    [
                        "git",
                        "-C",
                        REPO_ROOT,
                        "cat-file",
                        "-e",
                        f"{ref}:{p.replace(chr(92), '/')}",
                    ],
                    capture_output=True,
                ).returncode
                == 0
            )

    def check_paths(text: str, where: str, tag: str) -> None:
        # Step-local relative paths resolve against the step's
        # working-directory (falling back to the job default), not the repo
        # root; fall back to the ref's tree for non-checked-out refs.
        wd = step.get("working-directory") or job.get("defaults", {}).get(
            "run", {}
        ).get("working-directory", "")
        base = os.path.join(REPO_ROOT, wd.replace("\\", "/")) if wd else REPO_ROOT

        def local_exists(p: str) -> bool:
            if os.path.exists(os.path.join(base, p)):
                return True
            return ref != "HEAD" and exists(p)

        for tok in sorted(set(PATH_TOKEN.findall(text))):
            # Skip option strings, globs and shell builtins.
            if tok.startswith("-") or "*" in tok:
                continue
            p = tok.replace("\\", "/")
            while p.startswith("./"):
                p = p[2:]
            if not local_exists(p):
                add(P1, f"{tag}: {where} references missing path '{tok}'")

    for name in names:
        raw = read(name)
        # A workflow blob that itself starts with a conflict marker is a P0:
        # GitHub cannot parse it and every run becomes a 0-job startup failure.
        if CONFLICT_OPEN.match(raw.split(b"\n", 1)[0]):
            add(P0, f"{ref}:{name}: file starts with a merge-conflict marker")
        try:
            doc = yaml.safe_load(raw.decode("utf-8-sig"))
        except Exception as e:  # noqa: BLE001 - yaml errors vary
            add(P0, f"{ref}:{name}: YAML parse error: {e}")
            continue
        if not isinstance(doc, dict):
            add(P0, f"{ref}:{name}: top level is not a mapping")
            continue
        # PyYAML 1.1 unquotes `on:` to the boolean True - accept either key.
        if "on" not in doc and True not in doc:
            add(P0, f"{ref}:{name}: missing 'on' trigger block")
        if "jobs" not in doc:
            add(P0, f"{ref}:{name}: missing 'jobs' block")

        for jid, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                add(P0, f"{ref}:{name}: job {jid} is not a mapping")
                continue
            if not job.get("runs-on"):
                add(P0, f"{ref}:{name}: job {jid} missing runs-on")
            for i, step in enumerate(job.get("steps") or []):
                tag = f"{ref}:{name}: job {jid} step {i + 1}"
                shell = step.get("shell")
                if shell and shell not in VALID_SHELLS:
                    add(
                        P0,
                        f"{tag}: invalid shell '{shell}' - step can never run",
                    )
                uses = step.get("uses")
                if uses and "@" not in uses:
                    add(P1, f"{tag}: uses '{uses}' without a version ref")

                for key in ("run", "with", "working-directory"):
                    val = step.get(key)
                    if isinstance(val, str):
                        check_paths(val, key, tag)
                    elif isinstance(val, dict):
                        for k, v in val.items():
                            if isinstance(v, str):
                                check_paths(v, f"{key}.{k}", tag)


# ---------------------------------------------------------------------------
# 3. Committed merge conflicts at a ref
# ---------------------------------------------------------------------------
def scan_conflicts(ref: str) -> None:
    listing = git("ls-tree", "-r", "--name-only", ref).decode("utf-8", "replace")
    candidates = []
    markers = git("grep", "-I", "-l", "-E", r"^<<<<<<< ", ref, "--")
    for line in markers.decode("utf-8", "replace").splitlines():
        path = line.split(":", 1)[1] if ":" in line else line
        if "node_modules" in path:
            continue
        candidates.append(path)
    for path in sorted(set(candidates)):
        data = git("cat-file", "blob", f"{ref}:{path}")
        if blob_has_conflict(data):
            lines = data.split(b"\n")
            add(
                P0,
                f"{ref}:{path}: unresolved merge-conflict block "
                f"({len(lines)} lines, opens with {lines[0].decode('utf-8', 'replace')!r})",
            )


def blob_has_conflict(data: bytes) -> bool:
    state = 0
    for line in data.splitlines():
        if state == 0 and CONFLICT_OPEN.match(line):
            state = 1
        elif state == 1 and CONFLICT_SEP.match(line):
            state = 2
        elif state == 2 and CONFLICT_CLOSE.match(line):
            return True
        elif state == 2 and CONFLICT_OPEN.match(line):
            state = 1
    return False


# ---------------------------------------------------------------------------
# 4. Non-UTF-8 BOMs in tracked text files (cmake/git toolchain rejects these)
# ---------------------------------------------------------------------------
def scan_boms(ref: str) -> None:
    roots = (".github/", "cmake/", "ci/", "scripts/", "tools/")
    listing = git("ls-tree", "-r", "--name-only", ref).decode("utf-8", "replace")
    for path in listing.splitlines():
        if not path.endswith((".txt", ".cmake", ".yml", ".yaml", ".md")) and not any(
            path.startswith(r + "CMakeLists") for r in roots
        ):
            continue
        if not path.startswith(roots) and os.path.basename(path) != "CMakeLists.txt":
            continue
        data = git("cat-file", "blob", f"{ref}:{path}")
        if data.startswith(b"\xff\xfe"):
            add(P0, f"{ref}:{path}: UTF-16 LE BOM - cmake/toolchain cannot parse")
        elif data.startswith(b"\xfe\xff"):
            add(P0, f"{ref}:{path}: UTF-16 BE BOM - cmake/toolchain cannot parse")


# ---------------------------------------------------------------------------
# Live checks (optional)
# ---------------------------------------------------------------------------
def check_live(repo: str) -> None:
    def gh(*args: str):
        return subprocess.run(
            ["gh", *args], capture_output=True
        ).stdout

    try:
        out = gh("api", f"repos/{repo}/actions/runs?per_page=50")
        runs = json.loads(out or b"{}").get("workflow_runs", [])
    except Exception as e:  # noqa: BLE001
        add(P2, f"live: cannot list runs ({e})")
        return

    zero_job_failures = 0
    for r in runs:
        if r.get("conclusion") == "failure" and r.get("run_attempt", 1) >= 1:
            zero_job_failures += 1
    failed = [r for r in runs if r.get("conclusion") == "failure"]
    ok = [r for r in runs if r.get("conclusion") == "success"]
    print(
        f"live: {len(runs)} recent runs -> {len(failed)} failure, "
        f"{len(ok)} success"
    )
    for r in failed[:15]:
        print(
            f"  FAIL {r['created_at']} {r['name']} on {r['head_branch']} "
            f"(run {r['id']})"
        )
        add(
            P1,
            f"live: workflow '{r['name']}' failed on {r['head_branch']} "
            f"at {r['created_at']} (run {r['id']})",
        )

    # Flag runs whose workflow file is conflicted (0-job startup failures).
    out = gh("api", f"repos/{repo}/actions/runs?per_page=50&status=completed")
    for r in json.loads(out or b"{}").get("workflow_runs", []):
        jobs = json.loads(
            gh("api", f"repos/{repo}/actions/runs/{r['id']}/jobs") or b"{}"
        )
        if r.get("conclusion") == "failure" and jobs.get("total_count") == 0:
            add(
                P0,
                f"live: run {r['id']} of '{r['name']}' on {r['head_branch']} "
                f"failed with 0 jobs (startup failure - invalid workflow file)",
            )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--repo", default="futureofconsciousness/RawrXD")
    args = ap.parse_args()

    print(f"[1/4] validating workflow YAML and referenced paths at {args.ref}")
    validate_workflow(args.ref)
    print(f"[2/4] scanning {args.ref} tree for committed merge conflicts")
    scan_conflicts(args.ref)
    print(f"[3/4] scanning {args.ref} tree for non-UTF-8 BOMs in text files")
    scan_boms(args.ref)
    if args.live:
        print("[4/4] querying live GitHub run history")
        check_live(args.repo)
    else:
        print("[4/4] live checks skipped (use --live)")

    order = [P0, P1, P2]
    counts = {s: sum(1 for sev, _ in findings if sev == s) for s in order}
    print(
        "\n=== findings: "
        + ", ".join(f"{s}: {counts[s]}" for s in order)
        + " ==="
    )
    for sev in order:
        for s, msg in findings:
            if s == sev:
                print(f"  [{s}] {msg}")
    return 1 if counts[P0] or counts[P1] else 0


if __name__ == "__main__":
    sys.exit(main())
