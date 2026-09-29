# RawrXD Scale Value Pack

This drop intentionally does **not** replace Deep2 or the existing sovereign
agent loop. It adds the operational surfaces that current agentic IDE products
use to scale work safely:

- persistent local workspace index
- durable checkpoints
- isolated task workspaces
- captured run artifacts
- parallel agent processes
- conflict-safe merge back to the real workspace
- deterministic PASS/HOLD receipts

## Files

- `rawrxd_scale_value_pack.cpp` — complete C++20 implementation
- `RawrXDScaleValuePack.cmake` — build target
- `certify_rawrxd_scale_value_pack.ps1` — real local certification script

## Drop paths

```text
src/agentic/rawrxd_scale_value_pack.cpp
cmake/RawrXDScaleValuePack.cmake
scripts/certify_rawrxd_scale_value_pack.ps1
```

Then add:

```cmake
include(cmake/RawrXDScaleValuePack.cmake)
```

## Build

```powershell
cmake -S F:\~dev\rawrxd -B F:\~dev\build_scale -G Ninja `
  -DCMAKE_BUILD_TYPE=Release

cmake --build F:\~dev\build_scale --target RawrXD-Scale
```

## Index + search

```powershell
F:\~dev\build_scale\RawrXD-Scale.exe index `
  --workspace F:\~dev\rawrxd

F:\~dev\build_scale\RawrXD-Scale.exe search `
  --workspace F:\~dev\rawrxd `
  --query "Deep2 generate stream chat callback" `
  --top 20
```

## Checkpoints

```powershell
F:\~dev\build_scale\RawrXD-Scale.exe checkpoint-create `
  --workspace F:\~dev\rawrxd `
  --label before-chat-e2e

F:\~dev\build_scale\RawrXD-Scale.exe checkpoint-list `
  --workspace F:\~dev\rawrxd
```

Restore is deliberately explicit because it changes files:

```powershell
F:\~dev\build_scale\RawrXD-Scale.exe checkpoint-restore `
  --workspace F:\~dev\rawrxd `
  --id <checkpoint-id>
```

## One isolated agent

```powershell
F:\~dev\build_scale\RawrXD-Scale.exe run-isolated `
  --agent-exe F:\~dev\build_agentic\RawrXD-Agentic.exe `
  --workspace F:\~dev\rawrxd `
  --model G:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf `
  --task "Fix the strict Win32IDE chat-to-Deep2 path, build it, and verify token streaming." `
  --max-steps 48 `
  --max-tokens 8192 `
  --timeout-minutes 90 `
  --merge
```

The session executes in:

```text
<workspace>\.rawrxd\sessions\<session-id>\workspace
```

The original workspace is untouched until merge. Merge only applies a file if
the original file still has the exact hash captured when the session started.
Otherwise the file is reported as a conflict and is not overwritten.

Every merge first creates a durable checkpoint.

## Parallel agents

Create a task file with one independent task per line:

```text
Audit and fix strict Win32IDE chat dispatch. Build and verify.
Audit and fix model selection persistence. Build and verify.
Audit and fix shutdown/lifetime after generation. Build and verify.
```

Run:

```powershell
F:\~dev\build_scale\RawrXD-Scale.exe run-many `
  --agent-exe F:\~dev\build_agentic\RawrXD-Agentic.exe `
  --workspace F:\~dev\rawrxd `
  --model G:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf `
  --tasks F:\~dev\rawrxd-scale-tasks.txt `
  --max-workers 2 `
  --max-steps 40 `
  --max-tokens 8192 `
  --timeout-minutes 90 `
  --merge
```

Because every worker starts from an isolated copy, two agents cannot corrupt the
same live working tree. Sequential merge uses the baseline hash to detect
overlap. The first non-conflicting result can merge; later overlapping results
become explicit conflicts instead of silently overwriting work.

## Artifact layout

```text
.rawrxd/
  index/
    workspace.rxidx
  checkpoints/
    <checkpoint-id>/
      metadata.json
      manifest.tsv
      files/...
  sessions/
    <session-id>/
      request.json
      baseline.tsv
      stdout.log
      changes.tsv
      result.json
      merge.json
      workspace/...
```

## Important boundary

This executable launches the existing `RawrXD-Agentic.exe`, which remains the
Deep2 authority. It does not add an HTTP server, cloud model provider, Ollama,
llama.cpp, or a second inference stack.
