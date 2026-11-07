# RawrXD native compiler / builder / linker contract

**Status:** model-free build orchestration with real compiler/linker execution, not a
new C/C++ front end. The portable adapter is tested on Linux. The separate
RawrXD COFF/PE linker, Windows/MSVC integration, and complete IDE GUI use
remain certification gates; a source-only check is never a runtime PASS.

## Canonical entry point

\`python tools/rawrxd_native_toolchain.py <operation> --workspace <absolute-root> --output <relative-artifact> [arguments]\`

Operations are: \`compile\`, \`link\`, \`build\`, \`project\`, and read-only \`verify\`.

- **compile:** \`--source a.c --format pe --output a.obj --approve-mutations\`
- **link:** \`--object a.obj --object b.obj --entry main --format pe --output app.exe --approve-mutations\`
- **build:** \`--source a.c --source b.c --entry main --format pe --output app.exe --approve-mutations\`
- **project:** \`--project-dir . --target MyTarget --artifact build-path-relative-to-CMake-build --format host --output shipped-program --approve-mutations\`
- **verify:** \`--format pe --output app.exe\` (no mutation approval required)

Example for a minimal x64 PE smoke fixture (no CRT):

\`\`\`sh
python tools/rawrxd_native_toolchain.py build \
  --workspace . --source tests/fixtures/main.c \
  --format pe --entry main --output out/minimal.exe \
  --approve-mutations
\`\`\`

On Windows, \`cl.exe\`/\`link.exe\` or \`clang-cl\`/\`lld-link\` are required for
PE generation; on Linux the latter pair cross-compiles a Windows PE image.
\`--format host\` currently checks **x86-64 ELF** and is intended for Linux.
\`project\` uses CMake configure/build with an ephemeral build directory,
then publishes only a validated linked artifact.

The direct PE mode intentionally passes \`/nodefaultlib\` and an explicit
entry point. It is suitable for freestanding entry-point and relocation
smokes, **not** arbitrary C++ projects requiring the Windows CRT, SDK or
runtime libraries. Use the CMake project mode with your configured MSVC
toolchain for those projects.

## Model/IDE tool adapter policy

The output is exactly one JSON object on stdout. Status is grounded in the
actual process exit code **and** existence/format verification of a newly
staged artifact:

- \`ok\`: boolean, never true after a compiler/linker failure;
- \`operation\` and \`format\`: requested operation and binary target;
- \`commands\`: subprocess argument vectors, real exit codes, bounded stdout
  and stderr (diagnostics, up to 32 KiB each);
- on success: \`artifact\`, validated \`type\`, SHA-256 \`sha256\`;
- on failure: \`error\`, \`code\`.

Exit codes: 0 verified success; 2 invalid request; 3 path/policy/approval
denial; 4 compile/link/build/process failure; 5 missing/disallowed tool;
6 artifact structure/presence failure.

All mutating operations require an explicit \`--approve-mutations\` decision
from the caller. **Do not** infer user approval from the model's own requested
tool arguments, and do not silently add this flag in an agent bridge. Paths
are normalized and checked against the caller-supplied workspace. Commands
are invoked via \`subprocess.run(argv)\`, never through a shell. Every result
is built in a private staging directory and atomically published only after
verification, preventing stale output from falsely passing.

The adapter is not a sandbox against malicious source code, malicious CMake
scripts, or races in a concurrently writable workspace: only build trusted
projects with your explicit authorization. No external inference service or
model is required.

## Executable evidence and remaining gates

\`\`\`sh
python -m unittest discover -s tools/tests -p test_native_toolchain.py -v
cmake -S src/toolchain/linker -B build/linker -G Ninja
cmake --build build/linker --parallel
ctest --test-dir build/linker --output-on-failure -V
\`\`\`

The first command runs the adapter acceptance suite. The last three operate
on **RawrXD's separate native PE/COFF linker** and test real COFF-to-PE
generation and negative cases. Do not substitute success from the external
\`lld-link\` adapter for certification of \`rawrxd_link\`.

The production native CMake graph exposes \`RawrXD-PELinker\`,
\`RawrXD-COFFCheck\`, and \`RawrXD-NativeToolchain-Acceptance\` through
\`~dev/rawrxd/cmake/NativeToolchain.fragment.cmake\`. It installs
\`rawrxd_link\`, \`rawrxd_check\`, and the Python adapter.

**OPEN:** clean MSVC build, RawrXD native-linker positive acceptance,
third-party ABI/CRT compatibility, full IDE menu/agent tool registration,
request approval propagation, and packaged Windows end-to-end smoke.
No claims of 100% IDE/linker readiness until these are exercised.
