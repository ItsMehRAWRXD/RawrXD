#!/usr/bin/env python3
"""
guard.py

Pipeline-facing wrapper for the Sovereign MASM Guard.

Build:
  ml64 /c guard.asm /Fo guard.obj
  link /DLL /NOENTRY /OUT:guard.dll /EXPORT:GuardBinary guard.obj

Verify:
  python guard.py verify <binary_path>
"""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path


class GuardError(RuntimeError):
    pass


DEFAULT_TOOL_DIR = Path(r"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64")
DEFAULT_ML64 = DEFAULT_TOOL_DIR / "ml64.exe"
DEFAULT_LINK = DEFAULT_TOOL_DIR / "link.exe"


def _candidate_tool_paths(name: str) -> list[Path]:
    candidates: list[Path] = []

    if name.lower() == "ml64.exe":
        candidates.extend(
            [
                Path(r"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe"),
                Path(r"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"),
                Path(r"C:\Program Files\Microsoft Visual Studio\18\Enterprise\SDK\ScopeCppSDK\vc15\VC\bin\ml64.exe"),
            ]
        )
    elif name.lower() == "link.exe":
        candidates.extend(
            [
                Path(r"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"),
                Path(r"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"),
                Path(r"C:\Program Files\Microsoft Visual Studio\18\Enterprise\SDK\ScopeCppSDK\vc15\VC\bin\link.exe"),
            ]
        )

    return candidates


def _resolve_tool(explicit: Path | None, default_path: Path, name: str) -> str:
    if explicit is not None:
        if not explicit.exists():
            raise GuardError(f"{name} not found at explicit path: {explicit}")
        return str(explicit)

    if default_path.exists():
        return str(default_path)

    for candidate in _candidate_tool_paths(name):
        if candidate.exists():
            return str(candidate)

    from_path = shutil.which(name)
    if from_path:
        return from_path

    raise GuardError(
        f"Unable to resolve {name}. Expected at {default_path} or in PATH."
    )


def build_guard(
    asm_path: Path,
    dll_path: Path,
    ml64_path: Path | None = None,
    link_path: Path | None = None,
) -> Path:
    asm_path = asm_path.resolve()
    dll_path = dll_path.resolve()
    obj_path = dll_path.with_suffix(".obj")
    work_dir = asm_path.parent

    ml64 = _resolve_tool(ml64_path, DEFAULT_ML64, "ml64.exe")
    link = _resolve_tool(link_path, DEFAULT_LINK, "link.exe")

    if not asm_path.exists():
        raise GuardError(f"guard asm source not found: {asm_path}")

    compile_cmd = [ml64, "/c", "/W3", "/nologo", str(asm_path), f"/Fo{obj_path.name}"]
    link_cmd = [
        link,
        "/DLL",
        "/NOENTRY",
        f"/OUT:{dll_path}",
        "/EXPORT:GuardBinary",
        str(obj_path),
    ]

    subprocess.run(compile_cmd, check=True, cwd=str(work_dir))

    # ml64 writes output relative to cwd. Move/copy if needed.
    produced_obj = work_dir / obj_path.name
    if produced_obj.exists() and produced_obj.resolve() != obj_path:
        obj_path.write_bytes(produced_obj.read_bytes())
    if not obj_path.exists() and produced_obj.exists():
        obj_path = produced_obj

    if not obj_path.exists():
        raise GuardError(f"Assembler did not produce object file: {obj_path}")

    subprocess.run(link_cmd, check=True, cwd=str(work_dir))
    return dll_path


def _load_guard(dll_path: Path) -> ctypes.CDLL:
    if not dll_path.exists():
        raise GuardError(f"guard dll not found: {dll_path}")

    guard = ctypes.CDLL(str(dll_path))
    guard.GuardBinary.argtypes = [ctypes.c_void_p]
    guard.GuardBinary.restype = ctypes.c_int
    return guard


def verify_binary_safety(
    file_path: str | Path,
    guard_dll: str | Path | None = None,
    rebuild_if_missing: bool = True,
    ml64_path: Path | None = None,
    link_path: Path | None = None,
) -> bool:
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        raise GuardError(f"Binary not found: {file_path}")

    base_dir = Path(__file__).resolve().parent
    dll_path = Path(guard_dll).resolve() if guard_dll else (base_dir / "guard.dll")
    asm_path = base_dir / "guard.asm"

    if not dll_path.exists():
        if not rebuild_if_missing:
            raise GuardError(f"Guard DLL missing: {dll_path}")
        build_guard(asm_path, dll_path, ml64_path=ml64_path, link_path=link_path)

    guard = _load_guard(dll_path)

    data = file_path.read_bytes()
    if not data:
        raise GuardError("Security Guard: Empty file payload")

    buffer = ctypes.create_string_buffer(data, len(data))
    ptr = ctypes.cast(buffer, ctypes.c_void_p)
    result = int(guard.GuardBinary(ptr))

    if result == 0:
        return True
    if result == 1:
        raise GuardError("Security Guard: Invalid PE Header")
    if result == 2:
        raise GuardError("Security Guard: W^X Violation Detected (CRITICAL)")
    raise GuardError(f"Security Guard: Unknown return code {result}")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sovereign MASM guard build/verify tool")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build guard.dll from guard.asm")
    build.add_argument("--asm", default="guard.asm", help="Path to guard.asm")
    build.add_argument("--dll", default="guard.dll", help="Output DLL path")
    build.add_argument("--ml64", default=None, help="Explicit ml64.exe path")
    build.add_argument("--link", default=None, help="Explicit link.exe path")

    verify = sub.add_parser("verify", help="Verify a binary through the guard")
    verify.add_argument("binary", help="Path to binary to verify")
    verify.add_argument("--dll", default="guard.dll", help="Path to guard.dll")
    verify.add_argument("--ml64", default=None, help="Explicit ml64.exe path")
    verify.add_argument("--link", default=None, help="Explicit link.exe path")
    verify.add_argument(
        "--no-build",
        action="store_true",
        help="Do not auto-build guard.dll if missing",
    )

    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    base_dir = Path(__file__).resolve().parent

    try:
        if args.command == "build":
            asm = Path(args.asm)
            dll = Path(args.dll)
            if not asm.is_absolute():
                asm = base_dir / asm
            if not dll.is_absolute():
                dll = base_dir / dll
            build_guard(
                asm,
                dll,
                ml64_path=Path(args.ml64) if args.ml64 else None,
                link_path=Path(args.link) if args.link else None,
            )
            print(f"[PASS] Built guard DLL: {dll}")
            return 0

        if args.command == "verify":
            dll = Path(args.dll)
            if not dll.is_absolute():
                dll = base_dir / dll
            ok = verify_binary_safety(
                args.binary,
                guard_dll=dll,
                rebuild_if_missing=not args.no_build,
                ml64_path=Path(args.ml64) if args.ml64 else None,
                link_path=Path(args.link) if args.link else None,
            )
            if ok:
                print(f"[PASS] Guard approved binary: {Path(args.binary).resolve()}")
                return 0

        return 1
    except subprocess.CalledProcessError as exc:
        print(f"[FAIL] Guard toolchain command failed with exit code {exc.returncode}", file=sys.stderr)
        return 2
    except GuardError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
