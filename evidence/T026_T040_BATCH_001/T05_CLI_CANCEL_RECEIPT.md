# T05 CLI cancellation and shutdown receipt

## Candidate

```ini
BINARY=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
SIZE=5020160
SHA256=CCDBBBD061E5CEC328B08DF03B27F2D0593713EB3DA87FED4AC973775583925D
SOURCE_HEAD=4e9447beecaf85963859c487d29e86473560ceca
```

## Controlled runs

### Normal one-shot

```ini
COMMAND=rawr run qwen3:8b --backend ollama --workspace F:\rawrxd --max-tokens 128 --context 8192 --fresh-session --prompt "Reply with exactly CLI_NORMAL_OK"
EXIT=0
OUTPUT_MARKER=CLI_NORMAL_OK
PROCESS_EXITED=1
```

### Cancellation

```ini
COMMAND=rawr run qwen3:8b --backend ollama --workspace F:\rawrxd --max-tokens 4096 --context 65536 --cancel-after-ms 250 --prompt "Generate a long technical explanation of Windows diagnostics and continue for as long as possible."
EXIT=130
ELAPSED_MS=2378
CANCEL_MESSAGE=[agent] CANCELLED: user_interrupt
PROCESS_EXITED=1
TIMEOUT_KILL=0
```

The trace reached `BackendRouter::Shutdown:done` after the active Deep2 health request was closed. The optional CLI health poller was disabled for one-shot commands, so no background health worker remained to delay exit. This is a real transport/shutdown receipt, not a timeout classified as success.

## Disposition

```ini
T05_CLI_CANCEL=PASS
CHILD_PROCESS_CLEANUP=PASS
IDE_CANCELLATION=SEPARATE_GATE
PROMOTE=0
CERTIFIED=0
```
