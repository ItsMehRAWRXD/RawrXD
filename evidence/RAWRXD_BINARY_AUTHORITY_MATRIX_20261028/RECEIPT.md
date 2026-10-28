# RawrXD Binary Authority Matrix — 2026-10-28

## Authority

```ini
PRODUCT_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
EXPECTED_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
REBUILD_THIS_DISPATCH=0
PROMOTE=0
TIP_CLIMB=HOLD
PRODUCT_CERTIFIED=0
GHOSTTEXT_SCOPE=WITNESS_ONLY
```

The frozen product was executed directly. No build-tree executable was used
for this matrix, and the frozen file hash matched before and after each run.

## Inputs

| Model | Path | SHA-256 | Size |
|---|---|---|---:|
| TinyLlama | `G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` | `9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0` | 668,788,096 |
| Gemma3 | `G:\~dev\rawrxd\models\gemma3-1b-Q2_K.gguf` | `ADBD048B1738782BC13819C08C3A14F7FBE9633B13E84D04DE96B57E106C6E08` | 699,066,720 |

## Exact test

```text
RawrXD-Win32IDE.exe --headless --local --no-server --model <model> --prompt "Say hi in one word." --max-tokens 16 --backend local --verbose
Environment: RAWRXD_HEADLESS=1
Working directory: G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin
```

Raw process streams are preserved in this directory as `<Model>.stdout.txt`
and `<Model>.stderr.txt`.

## Results

### TinyLlama

```ini
EXECUTABLE_SHA256_BEFORE=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
EXECUTABLE_SHA256_AFTER=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
EXIT_CODE=0
MODEL_OPEN=PASS
SESSION_ENTER=PASS
GENERATED_TOKENS=16
TOKENS_COMMITTED=16
PRODUCT_E2E_MARKER=PASS
RAW_STDOUT=TinyLlama.stdout.txt
RAW_STDERR=TinyLlama.stderr.txt
```

TinyLlama satisfies the frozen-product generation and exit-code gates for this
run. Numerical correctness, semantic quality, and performance remain separate
gates.

### Gemma3

```ini
EXECUTABLE_SHA256_BEFORE=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
EXECUTABLE_SHA256_AFTER=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
EXIT_CODE=-1
MODEL_OPEN=PASS
SESSION_ENTER=PASS
GENERATED_TOKENS=NOT_OBSERVED
TOKENS_COMMITTED=NOT_OBSERVED
PRODUCT_E2E=NOT_PASS
RAW_STDOUT=Gemma3.stdout.txt
RAW_STDERR=Gemma3.stderr.txt
```

Gemma3 reaches model load and session admission but does not reach a generated
or committed token in the captured run. It is not cross-family certified.

## Disposition

```ini
TINYLLAMA_PRODUCT_GENERATION=PASS_FOR_THIS_RUN
GEMMA3_PRODUCT_GENERATION=FAIL_OR_INCOMPLETE
SAME_BINARY_SHA=PASS
CROSS_FAMILY_CERTIFICATION=NOT_CERTIFIED
NUMERICAL_CORRECTNESS=NOT_VERIFIED
PERFORMANCE=NOT_VERIFIED
PROMOTE=0
```
