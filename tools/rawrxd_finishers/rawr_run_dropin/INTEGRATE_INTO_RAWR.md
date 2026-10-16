# RawrXD one-command agent finishers

## Build standalone (MSVC x64 Developer PowerShell)

```powershell
cmake -S F:\rawrxd\tools\rawr_run_dropin -B F:\rawrxd\build_rawr_run -A x64
cmake --build F:\rawrxd\build_rawr_run --config Release
ctest --test-dir F:\rawrxd\build_rawr_run -C Release --output-on-failure
```

Copy this folder into `F:\rawrxd\tools\rawr_run_dropin` before running the build commands. No third-party packages; Windows WinHTTP is an OS component.

## Optional instant `rawr run` command in the current PowerShell session

After building, if you cannot yet rebuild the existing `rawr.exe`, dot-source `activate.ps1` to define a PowerShell function named `rawr` for the current session. It forwards only `rawr run` to this agent runner and leaves other commands using the existing `rawr.exe`:

```powershell
. F:\rawrxd\tools\rawr_run_dropin\activate.ps1
rawr run qwen2.5-coder:32b "Inspect the workspace, repair defects, build and verify." --workspace F:\rawrxd
```

The helper expects the standalone binary at `tools\rawr_run_dropin\build\Release\rawr_run.exe` (or `build\rawr_run.exe`). Build in that folder using `cmake -S . -B build -A x64`, then `cmake --build build --config Release`.

## Test standalone immediately

```powershell
F:\rawrxd\build_rawr_run\Release\rawr_run.exe run qwen2.5-coder:32b "Inspect source, locate a defect, repair it and run tests." --backend deep2 --workspace F:\rawrxd
```

Default Deep2 HTTP endpoint: `http://127.0.0.1:11436/v1/chat/completions`. This expects the Deep2 OpenAI-compatible server to already be running, serving that exact model name, with non-streaming chat and the expected JSON response. For Ollama instead specify `--backend ollama` (default `127.0.0.1:11434/api/chat`).

## Make the existing `rawr.exe` own the `run` subcommand

**In the actual source file containing your CLI's `main(int argc, char** argv)` function**, add the declaration and dispatch **before** its existing argument branches:

```cpp
extern int rawr_run_main(int argc, char** argv);
if (argc > 1 && std::string_view(argv[1]) == "run")
    return rawr_run_main(argc, argv);
```

Then add this source to **the existing CLI target** in its CMakeLists.txt (replace `<your_cli_target>` with the real CMake target name):

```cmake
target_sources(<your_cli_target> PRIVATE ${CMAKE_SOURCE_DIR}/tools/rawr_run_dropin/rawr_run.cpp)
target_compile_definitions(<your_cli_target> PRIVATE RAWRXD_RUN_EMBEDDED)
target_link_libraries(<your_cli_target> PRIVATE winhttp)
```

This makes **`rawr run <model> "<task>"`** a native command inside your existing executable. Do not blindly add a new target called `rawr` or replace an existing `rawr.exe`; integrate into the actual CLI target.

## Behavioral contract

* Model replies with exactly one JSON tool object (`{"tool":"read","input":"file.cpp"}`), or a byte-counted `TOOL <name> <bytes>\n<payload>\nEND_TOOL` command, or `FINAL` / `BLOCKED`. JSON is preferred.
* The runner uses **actual tool results** to continue; invalid `gash` is rejected (not silently re-mapped to `bash`).
* Tool names: `read`, `list`, `grep`, `edit`, `write`, `exec`, `verify`.
* Reads and writes are confined to the chosen workspace. Model/binary/Git/build directories are protected against direct mutations. Existing files are edited only by a unique-search replacement, never via `write`. New files use exclusive create.
* `exec` uses direct process launch (not a shell); defaults to a small build/test/git-read allowlist. `--allow-exec` explicitly expands process permission and can run arbitrary local programs; use only for trusted workspaces and models. Build systems themselves can execute project-defined commands.
* Edits require successful build (`exec`) and successful tests (`verify`) **after the last mutation** for `VERIFIED_SUCCESS`. Other finals are `COMPLETED_UNVERIFIED` and exit 23. A `BLOCKED` or exhaustion returns nonzero. This is a minimal evidence gate, not proof of full functional correctness.
* Receipts append to an on-disk JSONL task log. Model token rates use server-reported counts; no fabricated TPS.
* Uses non-streaming HTTP to avoid NDJSON confusion. Windows uses WinHTTP; all JSON is parsed structurally, never with `rfind`.
* Because this drop-in does not include your existing SNAP parser, it implements a compatible length-framed **text** contract at the model/host boundary. It does **not** claim that it integrated your existing SNAP process supervisor or native Deep2 GGUF loader. Connect those in your repository if required.

## Known limits that must not be misrepresented

* Does not start the Deep2 server or load GGUF models itself; Deep2 must serve the model requested by its exact name.
* No persistent replay/resume, browser actions, multi-agent scheduling, transactional multi-file rollback, or extensive permissions UI.
* Tool payloads are capped at 256 KiB, responses 4 MiB, and read/grep outputs bounded.
* The current tool-return channel is a user message in the chat protocol; whether a given model obeys byte-framed tools depends on its instruction tuning and template.
* Local model-produced code is untrusted. Running even approved builds can execute repository-specific build scripts.

## Repeatable checks (self-tests + mocked real tool execution)

```powershell
ctest --test-dir F:\rawrxd\build_rawr_run -C Release --output-on-failure
```

A separate `test_e2e_mock.py` is provided as an **optional testing-only** standard-library fixture. On a system with Python, it drives both HTTP schemas against a local fake inference server, proves invalid `gash` is rejected, applies an actual edit, runs `cmake --build`, runs CTest, and checks the JSONL ledger. It does **not** test real-model tool generation or Windows process behavior. Production runner has no Python dependency.

### Exit statuses

* `0`: mutation followed by successful recognized build and verification; evidence gate satisfied
* `20`: model/backend/HTTP error
* `21`: repeated invalid model tool responses
* `22`: model reported blocked
* `23`: model final without sufficient build/test evidence (`COMPLETED_UNVERIFIED`)
* `24`: maximum tool turns reached
* `2`: runner setup error
