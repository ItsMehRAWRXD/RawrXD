# Native IDE serverless Deep2 chat acceptance — 2026-11-19

Sprint gate: **embedded Deep2-to-IDE inference with the HTTP server stopped**

## Verdict

```
NATIVE_IDE_CHAT=PASS
SERVERLESS=IN_PROCESS (no HTTP client, no llama.cpp server, no Ollama call)
BACKEND=Deep2Engine
EXECUTABLE_SHA256=823EFF628D361C5D739EA5EC7A1FFFAF9FE564B21EBF696AAFAB92F23CD24231
```

## What changed

`src/win32app/Win32IDE_lifecycle.cpp` — the `IDM_DEEP2_GGUF_PROBE` (9614) handler
previously hardcoded `F:\rawrxd\bench_min.gguf`, a file that does not exist in the
tree, so the IDE's embedded Deep2 probe could never load a model.

Now:

* model path comes from `RAWRXD_DEEP2_PROBE_MODEL` (env), falling back to the
  legacy fixed path when unset;
* the receipt records `model_env=SET|DEFAULT`, the resolved model path, and the
  bridge's `GetModelInfo()` (backend, context, vocab, layers, heads, hidden dim);
* the generated text is written to
  `evidence\TOP25_C08_C09_DEEP2_RESPONSE.txt`.

## Reproduction

```
# HTTP inference servers stopped
Get-Process llama-server | Stop-Process -Force
# listener check on inference ports
Get-NetTCPConnection -State Listen | Where LocalPort -in 8080,8081,11434
#   -> only 11434 (Ollama desktop app), no 8080/8081 listener

pwsh -File evidence\SAME_SHA_ACCEPTANCE_20261119\ide_deep2_probe.ps1 `
     -Model F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
```

Script actions: launch `RawrXD-Win32IDE-Native.exe` with
`RAWRXD_DEEP2_PROBE_MODEL` bound, wait for the main HWND, `PostMessage(WM_COMMAND,
9614)`, wait for the probe receipt, terminate the IDE.

## Observed output

`evidence\TOP25_C08_C09_DEEP2.log`

```
init=1 load=1 gen=1 gen_len=9 model=F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
model_info=Model: F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
Backend: Deep2Engine (GPU active)
Context: 2048
Vocab Size: 32000
Layers: 22
Heads: 32
Hidden Dim: 2048
```

`evidence\TOP25_C08_C09_DEEP2_RESPONSE.txt` (9 bytes, model-generated)

```
hang -->
```

## Why this is Deep2 and not a server

* `rawr backend status` reports `endpoint=in-process://Deep2Engine`,
  `active=deep2-native GGUF models/tinyllama.gguf`, `reachable=yes`.
* The IDE calls `Deep2Bridge::LoadModel` + `GenerateSync` in-process; there is no
  HTTP client in the path and no socket listener was present on 8080/8081.
* The model identity in `model_info` matches the GGUF actually loaded.

## Caveats

* `GPU Dispatches: 0` / `GPU Weight Bytes: 0` in `GetModelInfo()` while the
  backend line says `GPU active`: the counters are not populated on this path.
  Token generation is real; the GPU-utilisation claim is not evidenced here.
* Single prompt (`"ping"`), 8-token cap, one position — not a throughput or
  quality acceptance.
* The IDE process was terminated by the harness after the receipt was written.

## Remaining blockers

* `GPU Dispatches` counter not wired into the bridge status string.
* Quantized-model quality/TPS acceptance and strict logit parity remain OPEN.
* Sunshine targets remain absent from this checkout.