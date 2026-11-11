# ScreenPilot / Deep2 integration audit — 2026-10-22

## Finding

`https://screenpilot.tech/gui/ide_chatbot_standalone.html` is a browser client, not a Deep2 runtime. Its current contract is a loopback RawrXD server at `http://localhost:11435`. The page probes `/status`, `/api/status`, `/health`, and `/api/engine/capabilities`, then sends chat to `/v1/chat/completions` (with `/api/generate` and `/api/chat` fallbacks), model discovery to `/api/tags` or `/v1/models`, CLI actions to `/api/cli`, and agent tools to `/api/tool` plus file/tool endpoints.

The page explicitly disables Ollama fallback (`LOCAL_ONLY_NO_OLLAMA`) and its console reports `ide_chat_commands.js not found`, so a browser opened from the public URL cannot reach the in-process CLI by itself.

## Local evidence

- `Test-NetConnection` on ports 11435, 11436, and 8080 found no listener in the current checkout.
- The native CLI executable `F:/rawrxd/build/bin-msvc/Release/rawr.exe` now supports direct `rawr run <model> "<prompt>"`, `--agent`, `--swarm`, bounded iterations/workers, receipts, alias resolution, and Deep2 streaming.
- A CPU Llama smoke completed with exit 0 and a deterministic `rawr.run.receipt.v1` receipt, but its receipt correctly remains `full_model_certification=NOT_CERTIFIED`.
- A two-worker bounded swarm completed through the existing delegation manager and emitted lifecycle events, but it ran with CPU policy and is not an inference or certification claim.
- The focused CTest registration currently points at missing probe executables under `build/bin/Release`; those tests were therefore `Not Run`, even though the probe sources exist in the dirty workspace. This is a build/test-artifact blocker, not a passing test.
- GPU telemetry from the native smoke path is zero (`DEEP2_REAL_GPU_FORWARD=0`); the R9700 specialized quant probe is separate evidence and does not certify `rawr run` end-to-end GPU execution. The RX 7800 XT was absent from Vulkan enumeration in the recorded probe.

## Why local agentic use is incomplete

1. The web page expects a long-lived HTTP gateway, while `rawr run` is a one-shot CLI.
2. The current `src/api_server.cpp` has route names but `InitializeHttpServer`/`HandleClientConnections` are placeholders; it is not a usable listener.
3. The repository has an orphan `deep2_http_gateway.hpp` and integration tests, but no tracked implementation `.cpp` in this checkout.
4. `/api/tool` remains intentionally fail-closed in the existing API server. That is correct for security, but it means the page cannot execute tools until it is backed by the same MOTD/session/turn authorization gate used by the CLI.
5. The public page also references a missing `ide_chat_commands.js` asset, disabling its remote CLI convenience layer.

## Required closure

Build one tracked native gateway that owns a loaded Deep2 engine and exposes the page's loopback contract. It must reuse the CLI provider, model alias resolver, MOTD gate, tool registry, and receipt writer; support SSE/NDJSON streaming; and reject `/api/tool` unless the request carries a valid session/turn authorization. Do not use the stale simulated `gguf_api_server.cpp`, and do not enable certification from HTTP status or component probes.

Until that gateway is implemented and tested against the hosted page, the correct status is:

```ini
SCREENPILOT_UI = AVAILABLE
RAWR CLI_AGENT = WIRED_AND_SMOKE_TESTED
DEEP2_HTTP_GATEWAY = MISSING_IN_THIS_CHECKOUT
GUI_AGENTIC_EXECUTION = BLOCKED
FULL_MODEL_CERTIFICATION = NOT_CERTIFIED
```
