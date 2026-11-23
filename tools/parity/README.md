# Independent teacher-forced logit parity oracle

This tool compares logits already captured from an independent reference runtime (for example, llama.cpp) and RawrXD. It does not invoke either runtime and must not be described as an end-to-end inference test.

## Capture contract

Each input is UTF-8 JSON with:
- `metadata.model_sha256`: SHA-256 of the exact model artifact.
- `metadata.tokenizer_sha256`: SHA-256 of the exact tokenizer assets/configuration.
- `metadata.tokens`: exact teacher-forced token IDs, in order.
- `positions`: entries containing a unique integer `position` and a complete `logits` array for that position.

The comparator refuses mismatched model/tokenizer hashes, token sequences, position sets, vocabulary widths, duplicate positions, NaN, and infinity. This prevents accidental comparison of different runs.

## Run

```sh
python3 -m unittest discover -s tools/parity -p 'test_*.py' -v
python3 tools/parity/compare_logits.py reference.json rawrxd.json --output parity-report.json
```

Exit codes: `0` = thresholds met, `1` = valid comparison but thresholds failed, `2` = invalid/incomparable input.

Default gates: mean cosine >= 0.9989, minimum per-position cosine >= 0.9885, argmax agreement >= 95%, and maximum per-position RMSE <= 0.05. These are explicit initial engineering gates, not universal guarantees; adjust only with a documented model/quantization-specific rationale.

## Evidence and limitations

The JSON report includes per-position cosine, RMSE, argmax agreement, mismatched positions, threshold values, and a SHA-256 fingerprint of the canonical reference capture. Preserve both original input captures alongside the report for auditability.

A passing report establishes agreement between two supplied logit captures under the selected thresholds. It does not establish that either capture was generated correctly, that model loading/tokenization was correct, that GPU execution is correct, or that full IDE-to-inference integration works. Record runtime version, commit SHA, device, backend, quantization, and command line in the capture provenance before treating results as release evidence.
