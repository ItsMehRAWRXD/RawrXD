# EXTENSIONHOST_INTEGRATION_REPAIR_001 — test matrix

All rows are planned tests. None are PASS until executed against one exact candidate SHA.

| ID | Test | Expected evidence | Gate |
|---|---|---|---|
| R01 | Route ownership for GUI LocalServer | trace shows `ProductExtensionRuntime::HandleRoute` and no `product_thin` response | source/unit |
| R02 | Route ownership for HeadlessIDE | same assertion through `routeGuiProductRequest` | source/unit |
| R03 | CMake target membership | generated target/source manifest contains all runtime TUs | candidate build |
| R04 | Worker deployment | worker exists beside candidate IDE; SHA recorded | candidate build |
| R05 | Missing worker | fail-closed JSON, PID 0, explicit missing-path reason | focused test |
| R06 | Quoted ID/path | spaces, quotes, trailing slash survive argument parsing | focused process test |
| R07 | CreateProcess failure | immediate Windows error code recorded | focused fault test |
| R08 | Readiness success | child PID, ready signal, protocol version, and first request/response recorded | runtime |
| R09 | Readiness timeout | child cleaned up; no `active=true`; timeout reason recorded | runtime |
| R10 | Request/response IPC | real extension request receives correlated response | runtime |
| R11 | Graceful shutdown | stop signal, exit code, bounded wait, handles/PID cleared | runtime |
| R12 | Forced shutdown fallback | hung child terminated only after timeout | runtime |
| R13 | Full extension matrix | discovery, manifest, activation, commands, toggles, isolation all rerun | `EXTENSION_RUNTIME_MATRIX_003` |

