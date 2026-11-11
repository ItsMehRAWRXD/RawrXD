# Gate 5 — Real CLI Generation

Command:

```text
build_ide/bin/rawrxd_deep2_engine.exe F:\rawrxd\gemma3-1b-Q2_K.gguf "Say OK" 1
```

Model SHA-256: `ADBD048B1738782BC13819C08C3A14F7FBE9633B13E84D04DE96B57E106C6E08`

Observed:

- Model admitted and loaded: 340 tensors.
- Prompt tokens: `2`.
- Requested output: `1` token.
- Actual token emitted/committed: `1`, token id `16436`, piece `nh\xE1\xBA\xA5t`.
- Completion receipt: `generated=1 completed=1 cancelled=0 stop_reason=16 stop=COMPLETED`.
- Process exit: `0`.
- Model cleanup completed, including tensor release, cache reset, residency reset, device release, and stream shutdown.

Gate 5: `PASS` for bounded real generation.

The run also reported a hidden-state norm warning and zero GPU forward operation counters; those are retained as runtime observations and do not change the token-generation result.
