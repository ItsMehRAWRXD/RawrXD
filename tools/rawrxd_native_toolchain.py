#!/usr/bin/env python3
"""Model-free, local C/C++ compiler-builder-linker adapter for RawrXD.

Never runs a shell.  Any mutating operation requires explicit authorization.
PE outputs are verified as x64 PE32+ images; host outputs are checked as ELF.
This adapter uses installed native compilers/linkers, it does not implement a C++ compiler.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

TOOL_ALLOW = {
    "clang-cl", "cl", "lld-link", "link", "clang", "clang++", "gcc", "g++", "cc", "c++", "cmake"
}

class BuildError(Exception):
    def __init__(self, message, code=4):
        super().__init__(message)
        self.code = code


def within(root, path, *, must_exist=False):
    root = Path(root).resolve(strict=True)
    p = Path(path)
    p = (p if p.is_absolute() else root / p).resolve(strict=False)
    try:
        p.relative_to(root)
    except ValueError:
        raise BuildError("Path escapes workspace: " + str(path), 3)
    if must_exist and not p.exists():
        raise BuildError("Input path does not exist: " + str(path), 2)
    return p


def tool(name):
    if name is None:
        raise BuildError("No compiler/linker available", 5)
    p = Path(name)
    base = p.name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    if base not in TOOL_ALLOW:
        raise BuildError("Disallowed tool executable: " + name, 3)
    executable = shutil.which(name)
    if not executable:
        raise BuildError("Tool not found: " + name, 5)
    return executable


def default_tool(fmt, phase, language="c"):
    if fmt == "pe":
        names = ("clang-cl", "cl") if phase == "compile" else ("lld-link", "link")
    elif phase == "compile":
        names = ("clang++", "g++") if language == "c++" else ("clang", "gcc", "cc")
    else:
        names = ("clang++", "g++", "c++")
    for name in names:
        if shutil.which(name):
            return name
    raise BuildError("No supported " + phase + " tool for " + fmt, 5)


def kind(source):
    suffix = source.suffix.lower()
    if suffix in (".cpp", ".cc", ".cxx"):
        return "c++"
    if suffix == ".c":
        return "c"
    raise BuildError("Unsupported source type: " + source.name, 2)


def inspect(path, fmt, obj=False):
    b = Path(path).read_bytes()
    if fmt == "pe" and obj:
        if len(b) < 20:
            raise BuildError("COFF object too short", 6)
        machine, sections = struct.unpack_from("<HH", b)
        if machine != 0x8664 or not 0 < sections <= 96:
            raise BuildError("Not a valid AMD64 COFF object", 6)
        return "AMD64-COFF"
    if fmt == "pe":
        if len(b) < 256 or b[:2] != b"MZ":
            raise BuildError("Missing MZ signature", 6)
        peoff = struct.unpack_from("<I", b, 0x3c)[0]
        if not 0x40 <= peoff <= len(b) - 0x108 or b[peoff:peoff+4] != b"PE\x00\x00":
            raise BuildError("Invalid PE header offset or signature", 6)
        machine, sections = struct.unpack_from("<HH", b, peoff+4)
        optsize = struct.unpack_from("<H", b, peoff+20)[0]
        optoff = peoff + 24
        if machine != 0x8664 or not 0 < sections <= 96 or optsize < 0xf0 or optoff+optsize+40*sections > len(b):
            raise BuildError("Invalid AMD64 PE32+ headers", 6)
        magic, = struct.unpack_from("<H", b, optoff)
        entry, = struct.unpack_from("<I", b, optoff+16)
        image, = struct.unpack_from("<I", b, optoff+56)
        if magic != 0x20b or entry == 0 or image == 0:
            raise BuildError("Invalid PE32+ magic, entry, or image size", 6)
        return "AMD64-PE32+"
    if b[:4] != b"\x7fELF":
        raise BuildError("Missing host ELF signature", 6)
    if len(b) < 20 or b[4] != 2 or struct.unpack_from("<H", b, 18)[0] != 62:
        raise BuildError("Not an x86-64 ELF artifact", 6)
    return "x86_64-ELF"


def execute(argv, timeout, evidence):
    # argv is always a list, never shell=True; no interpolation or shell parsing.
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        evidence.append({"argv": argv, "returncode": 124, "stderr": "Process timed out"})
        raise BuildError("Compiler/linker timeout: " + Path(argv[0]).name, 4) from exc
    except OSError as exc:
        raise BuildError("Cannot launch tool: " + str(exc), 5) from exc
    evidence.append({"argv": argv, "returncode": p.returncode,
                     "stdout": p.stdout[-32768:], "stderr": p.stderr[-32768:]})
    if p.returncode:
        raise BuildError("Tool failed with exit code " + str(p.returncode), 4)


def compile_one(source, obj, fmt, preferred, timeout, evidence):
    compiler = tool(preferred or default_tool(fmt, "compile", kind(source)))
    base = Path(compiler).name.lower().removesuffix(".exe")
    if fmt == "pe":
        if base not in ("cl", "clang-cl"):
            raise BuildError("PE compiler must be cl or clang-cl", 3)
        args = [compiler, "/nologo", "/c", str(source), "/Fo" + str(obj), "/W4", "/WX"]
    else:
        if base not in ("cc", "c++", "clang", "clang++", "gcc", "g++"):
            raise BuildError("Host compiler must be clang/gcc", 3)
        args = [compiler, "-c", str(source), "-o", str(obj), "-Wall", "-Wextra", "-Werror", "-O0"]
        args.append("-std=c++17" if kind(source) == "c++" else "-std=c11")
    execute(args, timeout, evidence)
    if not obj.is_file() or obj.stat().st_size == 0:
        raise BuildError("Compiler did not produce an object", 6)
    return inspect(obj, fmt, obj=True)


def link_many(objects, output, fmt, preferred, entry, subsystem, timeout, evidence):
    linker = tool(preferred or default_tool(fmt, "link"))
    base = Path(linker).name.lower().removesuffix(".exe")
    if fmt == "pe":
        if base not in ("link", "lld-link"):
            raise BuildError("PE linker must be link or lld-link", 3)
        if not entry or not entry.isidentifier():
            raise BuildError("PE mode requires a valid explicit entry symbol", 2)
        args = [linker, "/nologo", "/machine:x64", "/nodefaultlib", "/subsystem:" + subsystem,
                "/entry:" + entry, "/out:" + str(output)] + [str(p) for p in objects]
    else:
        if base not in ("clang++", "g++", "c++", "clang", "gcc"):
            raise BuildError("Host linker must be clang/gcc", 3)
        args = [linker, "-o", str(output)] + [str(p) for p in objects]
    execute(args, timeout, evidence)
    if not output.is_file() or output.stat().st_size == 0:
        raise BuildError("Linker did not produce an executable", 6)
    return inspect(output, fmt)


def run(args):
    evidence = []
    result = {"ok": False, "operation": args.operation, "format": args.format, "commands": evidence}
    try:
        root = Path(args.workspace).resolve(strict=True)
        if not root.is_dir():
            raise BuildError("Workspace is not a directory", 3)
        if args.operation == "verify":
            artifact = within(root, args.output, must_exist=True)
            result.update({"type": inspect(artifact, args.format), "artifact": str(artifact),
                           "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "ok": True})
            return 0, result
        if not args.approve_mutations:
            raise BuildError("--approve-mutations required for compilation/linking", 3)
        output = within(root, args.output)
        if output == root or output.is_dir():
            raise BuildError("Output must be a file inside workspace", 3)
        inputs = [] if args.operation == "project" else [within(root, x, must_exist=True) for x in (args.source if args.operation != "link" else args.object)]
        if args.operation != "project" and (not inputs or not all(x.is_file() for x in inputs)):
            raise BuildError("At least one existing source/object required", 2)
        if output in inputs:
            raise BuildError("Output would overwrite an input", 3)
        if args.operation == "compile" and len(inputs) != 1:
            raise BuildError("compile accepts exactly one --source", 2)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Every output is built into a private temporary path, then atomically
        # published only after a successful tool exit and format validation.
        with tempfile.TemporaryDirectory(prefix=".rawrxd-toolchain-", dir=str(output.parent)) as temp:
            staging = Path(temp)
            if args.operation == "project":
                project = within(root, args.project_dir, must_exist=True)
                if not project.is_dir() or not (project / "CMakeLists.txt").is_file():
                    raise BuildError("Valid CMake project directory required", 2)
                if not args.artifact:
                    raise BuildError("--artifact relative build output required", 2)
                build_dir = staging / "cmake-build"
                cmake = tool("cmake")
                configure = [cmake, "-S", str(project), "-B", str(build_dir)]
                if args.generator:
                    configure += ["-G", args.generator]
                execute(configure, args.timeout, evidence)
                buildcmd = [cmake, "--build", str(build_dir), "--config", "Release"]
                if args.target:
                    buildcmd += ["--target", args.target]
                execute(buildcmd, args.timeout, evidence)
                candidate = within(build_dir, args.artifact)
                if not candidate.is_file():
                    raise BuildError("Requested CMake artifact is not a file", 6)
                artifact_type = inspect(candidate, args.format)
                staged = staging / ("output.exe" if args.format == "pe" else "output")
                shutil.copy2(candidate, staged)
            elif args.operation == "compile":
                staged = staging / ("output.obj" if args.format == "pe" else "output.o")
                artifact_type = compile_one(inputs[0], staged, args.format, args.compiler, args.timeout, evidence)
            elif args.operation == "link":
                staged = staging / ("output.exe" if args.format == "pe" else "output")
                for item in inputs:
                    inspect(item, args.format, obj=True)
                artifact_type = link_many(inputs, staged, args.format, args.linker,
                                          args.entry, args.subsystem, args.timeout, evidence)
            else:
                objects = []
                for i, source in enumerate(inputs):
                    obj = staging / ("obj" + str(i) + (".obj" if args.format == "pe" else ".o"))
                    compile_one(source, obj, args.format, args.compiler, args.timeout, evidence)
                    objects.append(obj)
                staged = staging / ("output.exe" if args.format == "pe" else "output")
                artifact_type = link_many(objects, staged, args.format, args.linker,
                                          args.entry, args.subsystem, args.timeout, evidence)
            digest = hashlib.sha256(staged.read_bytes()).hexdigest()
            os.replace(staged, output)
        result.update({"ok": True, "artifact": str(output), "type": artifact_type, "sha256": digest})
        return 0, result
    except BuildError as exc:
        result.update({"error": str(exc), "code": exc.code})
        return exc.code, result
    except (OSError, ValueError) as exc:
        result.update({"error": "Filesystem/toolchain error: " + str(exc), "code": 4})
        return 4, result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("compile", "link", "build", "project", "verify"))
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--object", action="append", default=[])
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--target")
    parser.add_argument("--artifact")
    parser.add_argument("--generator", choices=("Ninja", "Unix Makefiles", "Visual Studio 17 2022"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", choices=("pe", "host"), default="pe")
    parser.add_argument("--compiler")
    parser.add_argument("--linker")
    parser.add_argument("--entry", default="main")
    parser.add_argument("--subsystem", choices=("console", "windows"), default="console")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--approve-mutations", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.timeout > 3600:
        parser.error("--timeout must be 1..3600 seconds")
    code, result = run(args)
    print(json.dumps(result, sort_keys=True))
    return code

if __name__ == "__main__":
    sys.exit(main())
