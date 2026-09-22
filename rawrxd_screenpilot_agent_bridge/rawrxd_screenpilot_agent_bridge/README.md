# RawrXD ScreenPilot Local Agent Bridge

No external dependencies. Windows + MSVC/C++20 only.

This bridge gives `ide_chatbot.html` local agent access without granting browser
JavaScript direct filesystem/process privileges.

## Security boundary

- Binds **only** to `127.0.0.1`.
- Rejects non-local `Host` and `Origin` values.
- Uses an in-memory session token for privileged endpoints.
- The browser cannot choose an arbitrary executable.
- The browser cannot choose an arbitrary working directory outside `--workspace-root`.
- Cancellation kills the per-request Windows Job Object.
- No shell (`cmd.exe`, PowerShell, `system()`) is used.

## Execution path

```text
ide_chatbot.html
  -> 127.0.0.1:11437
  -> rawrxd_screenpilot_bridge.exe
  -> rawr.exe run <model> "<mode policy + prompt>"
  -> existing RawrXD CLI / Tool Authority / Deep2
  -> streamed NDJSON
  -> HTML output pane
```

This deliberately reuses the shipping `rawr run ...` path instead of creating a
second filesystem/terminal/Git implementation in the browser bridge.

## Build

Developer PowerShell:

```powershell
cd <this-drop>
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release -j8
```

## Run

Adjust the `rawr.exe` path to the actual shipping CLI:

```powershell
.\build\Release\rawrxd_screenpilot_bridge.exe `
  --rawr "F:\~dev\build_p2\Release\rawr.exe" `
  --workspace-root "F:\~dev" `
  --port 11437
```

Port `11437` is used intentionally so it cannot collide with the existing
RawrXD LocalServer on `11435`. If you later merge these routes into LocalServer,
point `screenpilot_agent.js` at `11435` and remove the standalone listener.

## HTML integration

1. Copy `web/screenpilot_agent.js` next to `F:\ide_chatbot.html`.
2. Merge the markup from `web/HTML_PATCH.html` into the existing agent/chat area.
3. Open the HTML.
4. The status should become `local bridge online`.
5. Select ASK / PLAN / BUILD / AGENT and run a prompt.

If your current HTML already has mode buttons/composer elements, keep the
existing markup and only map its element IDs/data attributes to the controller.

## Required authority condition

For this bridge to preserve the project's single-tool-authority design,
`rawr.exe run ...` must already enter the canonical RawrXD Agent/Tool Authority
path. If `rawr.exe` still bypasses that registry, fix that once in the CLI
entrypoint rather than adding privileged tool code here.

## End-to-end pass gate

A completion run should prove all of these:

```text
SCREENPILOT_BRIDGE_LOOPBACK_ONLY=PASS
SCREENPILOT_SESSION_GUARD=PASS
SCREENPILOT_WORKSPACE_BOUNDARY=PASS
SCREENPILOT_ASK_MODE=PASS
SCREENPILOT_PLAN_MODE=PASS
SCREENPILOT_BUILD_MODE=PASS
SCREENPILOT_AGENT_MODE=PASS
SCREENPILOT_CANCEL=PASS
SCREENPILOT_STREAMING=PASS
SCREENPILOT_CANONICAL_TOOL_AUTHORITY=PASS
```

Then run:

```powershell
.\tests\smoke_screenpilot_bridge.ps1 `
  -Model "<your-local-model>" `
  -Workspace "F:\~dev"
```

The final gate should include one real BUILD/AGENT task that performs:

```text
read -> search -> edit -> build -> test -> receipt
```

inside a disposable test file/target, confirming the HTML is no longer a
cosmetic chat shell.
