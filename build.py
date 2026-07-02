#!/usr/bin/env python3
"""
build.py

Day 8 artifact bundler for Sovereign IDE runtime.

What it does:
1) Optionally enforces a safety benchmark budget gate from exported JSON.
2) Builds frontend production assets (npm run build).
3) Bundles frontend dist + backend runtime into a single output directory.
4) Generates SHA256 checksums for all bundled files.

Usage examples:
  python build.py
    python build.py --benchmark-json D:/path/safety-benchmark-*.json --max-redact-overhead-pct 5
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, List


def _run(cmd: List[str], cwd: Path | None = None) -> None:
    print(f"[build] $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {result.returncode}: {' '.join(cmd)}")


def _resolve_npm_executable() -> str:
    """Resolve npm executable cross-platform (npm.cmd on Windows)."""
    npm = shutil.which("npm")
    if npm:
        return npm

    npm_cmd = shutil.which("npm.cmd")
    if npm_cmd:
        return npm_cmd

    raise RuntimeError("npm executable not found in PATH (tried npm and npm.cmd)")


def _env_truthy(name: str) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _detect_docker_socket() -> bool:
    # Linux/macOS docker daemon socket.
    if Path("/var/run/docker.sock").exists():
        return True

    # Windows / remote docker host configuration signals.
    if os.environ.get("DOCKER_HOST"):
        return True

    return False


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
      while True:
        chunk = f.read(1024 * 1024)
        if not chunk:
          break
        h.update(chunk)
    return h.hexdigest()


def _iter_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file():
            yield p


def _write_checksums(out_dir: Path) -> Path:
    sums_path = out_dir / "SHA256SUMS.txt"
    lines = []
    for p in sorted(_iter_files(out_dir)):
        if p.name == sums_path.name:
            continue
        rel = p.relative_to(out_dir).as_posix()
        lines.append(f"{_sha256_file(p)}  {rel}")
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return sums_path


def _git_rev(root: Path) -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True)
        return out.strip()
    except Exception:
        return "UNKNOWN"


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and bundle Sovereign IDE verified artifact")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--frontend-dir", type=Path, default=Path("frontend"))
    parser.add_argument("--backend-file", type=Path, default=Path("mock_backend.py"))
    parser.add_argument("--out-dir", type=Path, default=Path("dist/sovereign_ide"))
    parser.add_argument("--benchmark-json", type=Path, default=None)
    parser.add_argument("--max-redact-overhead-pct", type=float, default=5.0)
    parser.add_argument("--max-passthrough-overhead-pct", type=float, default=3.0)
    parser.add_argument("--skip-frontend-build", action="store_true")
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    frontend_dir = (repo_root / args.frontend_dir).resolve()
    backend_file = (repo_root / args.backend_file).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    perf_gate = (repo_root / "tools" / "perf_budget_gate.py").resolve()
    benchmark_runner = (repo_root / "tools" / "run_benchmark.py").resolve()
    regression_runner = (repo_root / "tools" / "run_regression.py").resolve()
    hazard_corpus = (repo_root / "tests" / "hazard_corpus.json").resolve()
    engine_dockerfile = (repo_root / "docker" / "engine.Dockerfile").resolve()
    compose_file = (repo_root / "compose.yaml").resolve()
    npm_exe = _resolve_npm_executable()

    # Operational isolation mode.
    docker_isolation = _env_truthy("DOCKER_ISOLATION")
    if "DOCKER_ISOLATION" not in os.environ and _docker_available() and _detect_docker_socket():
        os.environ["DOCKER_ISOLATION"] = "true"
        docker_isolation = True
        print("[build] Auto-enabled DOCKER_ISOLATION=true (Docker socket/host detected)")

    if not frontend_dir.exists():
        raise RuntimeError(f"Frontend directory not found: {frontend_dir}")
    if not backend_file.exists():
        raise RuntimeError(f"Backend file not found: {backend_file}")
    if not perf_gate.exists():
        raise RuntimeError(f"Performance gate script missing: {perf_gate}")
    if not benchmark_runner.exists():
        raise RuntimeError(f"Benchmark runner script missing: {benchmark_runner}")
    if not regression_runner.exists():
        raise RuntimeError(f"Regression runner script missing: {regression_runner}")
    if not hazard_corpus.exists():
        raise RuntimeError(f"Hazard corpus missing: {hazard_corpus}")
    if docker_isolation:
        if not engine_dockerfile.exists():
            raise RuntimeError(f"Engine Dockerfile missing: {engine_dockerfile}")
        if not compose_file.exists():
            raise RuntimeError(f"Compose file missing: {compose_file}")

    # Optional perf gate before creating the artifact.
    if args.benchmark_json is not None:
        bench = args.benchmark_json.resolve()
        if not bench.exists():
            raise RuntimeError(f"Benchmark JSON not found: {bench}")
        _run(
            [
                sys.executable,
                str(perf_gate),
                str(bench),
                "--max-redact-overhead-pct",
                str(args.max_redact_overhead_pct),
                "--max-passthrough-overhead-pct",
                str(args.max_passthrough_overhead_pct),
            ]
        )

    if not args.skip_frontend_build:
        _run([npm_exe, "run", "build"], cwd=frontend_dir)

    frontend_dist = frontend_dir / "dist"
    if not frontend_dist.exists():
        if args.skip_frontend_build:
            raise RuntimeError(
                f"Frontend build output not found: {frontend_dist}. "
                "Either run without --skip-frontend-build or generate frontend/dist first."
            )
        raise RuntimeError(f"Frontend build output not found: {frontend_dist}")

    # Clean output folder.
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Bundle frontend assets.
    shutil.copytree(frontend_dist, out_dir / "frontend", dirs_exist_ok=True)

    # Bundle backend and lock files.
    shutil.copy2(backend_file, out_dir / backend_file.name)

    requirements = repo_root / "requirements.txt"
    if requirements.exists():
        shutil.copy2(requirements, out_dir / "requirements.txt")

    # Bundle the performance gate for reproducible local verification.
    tools_dir = out_dir / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(perf_gate, tools_dir / "perf_budget_gate.py")
    shutil.copy2(benchmark_runner, tools_dir / "run_benchmark.py")
    shutil.copy2(regression_runner, tools_dir / "run_regression.py")

    tests_dir = out_dir / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(hazard_corpus, tests_dir / "hazard_corpus.json")

    if docker_isolation:
        docker_out = out_dir / "docker"
        docker_out.mkdir(parents=True, exist_ok=True)
        shutil.copy2(engine_dockerfile, docker_out / "engine.Dockerfile")
        shutil.copy2(compose_file, out_dir / "compose.yaml")

    # Build manifest for provenance.
    if docker_isolation:
        backend_launch = {
            "mode": "docker",
            "command": "docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --cap-add NET_BIND_SERVICE -p 11435:11435 sovereign-engine:latest",
        }
    else:
        backend_launch = {
            "mode": "native",
            "command": f"{sys.executable} {backend_file.name}",
        }

    manifest = {
        "artifact": "sovereign_ide",
        "builtAtEpochMs": int(time.time() * 1000),
        "gitCommit": _git_rev(repo_root),
        "python": sys.version,
        "frontendDir": str(frontend_dir),
        "backendFile": str(backend_file),
        "dockerIsolation": docker_isolation,
        "backendLaunch": backend_launch,
        "perfGate": {
            "benchmarkJson": str(args.benchmark_json.resolve()) if args.benchmark_json else None,
            "maxRedactOverheadPct": args.max_redact_overhead_pct,
            "maxPassthroughOverheadPct": args.max_passthrough_overhead_pct,
        },
    }
    (out_dir / "build_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    sums_path = _write_checksums(out_dir)

    print("[build] Bundle complete")
    print(f"[build] Output: {out_dir}")
    print(f"[build] Checksums: {sums_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
