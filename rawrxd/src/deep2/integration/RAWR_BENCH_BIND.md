# RawrXD integration: `rawr bench <model> --contract`

Recommended binding:

1. `rawr bench <model> --contract <name>`
2. Resolve/load real GGUF.
3. Convert GGUF metadata to `B66MetadataSource`.
4. `B66RuntimeMetaBinder::bind`.
5. Warm model until residency counters stabilize.
6. For each decode token, populate `B67TokenTelemetry` from real GPU timestamp/counter data.
7. Derive `B68WorkModel` from the actually executed bytes/token and FLOPs/token.
8. `B68TargetCalibrator::calibrate`.
9. Load the model's Batch 61–65 contract or a calibrated local contract.
10. `B69ContractRunner::run`.
11. Write `B70Receipt`.
12. Persist canonical receipt text + SHA-256.

Suggested CLI:

    rawr bench qwen3-next:80b --contract --tokens 384

Example fail-closed output:

    CONTRACT=qwen3-next-80b-a3b-q4-short
    SAMPLES=352
    PHYSICAL_ROOFLINE_TPS=...
    P10_TPS=...
    MEDIAN_TPS=...
    GPU0_FORWARDS=...
    GPU1_FORWARDS=...
    PARITY_ALL=1
    OUTPUT_STABLE_ALL=1
    CERT=PASS|HOLD
    FAILURE=...
    RECEIPT_SHA256=...

Rules:
- Never count warmup/prefill samples.
- Never substitute estimated bytes/token for executed-path counters when live counters exist.
- Never certify dual GPU if GPU1 forward count is zero.
- Never accept roofline fraction >1 without repairing the accounting.
- B70 SHA-256 is tamper evidence only, not a cryptographic signature/authenticity proof.
