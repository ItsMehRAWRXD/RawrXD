# Current CLI-hash cancellation stress receipt

```ini
ASOF_LOCAL=2026-11-04
SCOPE=CLI_ONLY
BINARY=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
BINARY_SIZE=5020160
BINARY_SHA256=706D52A24E4A688DFA0A74C20404CD49B8990AEB21815F830296D6C52FCB5847
MODEL=qwen3:8b
BACKEND=ollama
MAX_TOKENS=4096
CONTEXT=65536
CANCEL_AFTER_MS=250
PROMPT=long real generation request
CYCLES_COMPLETED=25
EXIT_CODE_EACH_CYCLE=130
CANCEL_RECEIPT_EACH_CYCLE=1
PASS_COUNT=25
FORCED_KILLS=0
ORPHAN_RAWR=0
```

The corrected workload included an actual long-generation prompt. A prior
no-prompt loop is intentionally not counted: it had no active inference to
cancel and returned exit 0, so it was an invalid cancellation test.

```ini
CANCELLATION_STRESS=PASS
PROCESS_EXIT_LATENCY_PER_CYCLE=NOT_MEASURED
WIN32IDE_CERTIFICATION=UNCHANGED
PROMOTE=0
CERTIFIED=0
```
