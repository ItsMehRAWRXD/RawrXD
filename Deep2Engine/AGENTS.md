# RawrXD Agent Hooks — AGENTS.md

This file configures customizable IDE hooks for the RawrXD Agentic IDE.
Agents can modify this file to run commands at IDE lifecycle events.
Hooks are parsed from `[hook:event]` sections.

## Hook Events

- startup      - IDE window created and ready
- file_open    - user opened a file
- file_save    - user saved a file
- build_start  - agent/build command started
- build_end    - agent/build command finished
- shutdown     - IDE window destroyed

## Placeholders

- {path} - full path of the file being opened/saved
- {name} - file name only
- {dir}  - directory of the file

[hook:startup]
echo "RawrXD Agentic IDE starting..."

[hook:file_open]
echo "Opened: {path}"

[hook:file_save]
echo "Saved: {path}"

[hook:build_start]
echo "Build starting for: {path}"

[hook:build_end]
echo "Build finished for: {path}"

[hook:shutdown]
echo "RawrXD Agentic IDE shutting down..."

## Agent-only native build mode

To test agents compiling with RawrXD's own toolchain only, add hooks that
invoke RawrXD-native compiler/linker binaries rather than MSVC/cl.exe or
external GCC/Clang. Example:

[hook:agent_build]
rawr build --native-only --source {path} --output {dir}/out.exe

No external compilers (MSVC, GCC, Clang, LLVM) may be invoked by hooks
configured in this file when COMPILER_MODE=RAWR_NATIVE_ONLY is set.
