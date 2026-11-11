# T05 CLI cancellation stress receipt

```ini
BINARY=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
SIZE=5020160
SHA256=CCDBBBD061E5CEC328B08DF03B27F2D0593713EB3DA87FED4AC973775583925D
MODEL=ollama/qwen3:8b
CANCEL_AFTER_MS=250
```

## Campaign

Twenty-five real one-shot processes were launched against the same executable. The harness observed cycles 1–24 in the first bounded batch and cycle 25 in a separate final receipt after confirming no `rawr.exe` process remained.

```ini
CYCLES_COMPLETED=25
EXIT_CODE_EACH_CYCLE=130
CANCEL_RECEIPT_EACH_CYCLE=1
TIMEOUT_KILLS=0
ORPHAN_RAWR_OBSERVATIONS=0
FINAL_CYCLE_ELAPSED_MS=2457
FINAL_CYCLE_CANCEL_MESSAGE=present
```

Observed cycle durations were approximately 2.38–2.46 seconds. Every completed process returned the cancellation exit code; no cycle required a forced kill, and no orphan `rawr.exe` process was observed after the campaign.

## Disposition

```ini
T05_CLI_CANCELLATION_STRESS=PASS
CLI_PROCESS_CLEANUP=PASS
WIN32_IDE_CANCELLATION=SEPARATE_GATE
DEEP2_HEALTH_THREAD_ACTIVE_SCENARIO=NOT_REPLAYED_ON_THIS_HASH
PROMOTE=0
CERTIFIED=0
```
