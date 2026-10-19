# RAWRXD_AUTHORITATIVE_TOKEN_RUNTIME_X64_MASM_NODEP

Pure x64 MASM, source-only, no third-party dependencies.

Purpose:
Convert raw live token-runtime counters into independently derived NILW witnesses.
The caller supplies measurements only. It cannot supply PASS states or derived
metrics.

Authority chain:

    RAW_RUNTIME_COUNTERS
            |
            v
    MASM DERIVED METRICS
            |
            v
    MASM DERIVED W01..W14
            |
            v
    W15 = conjunction reporter
            |
            v
    AUTHORIZED_PASS

Key laws:
- NOT_RUN != PASS.
- No caller-controlled witness_state array exists in the raw input structure.
- Form A and Form B numerators are mutually exclusive.
- TOKEN_NILW <= 0.0008 is actually enforced.
- ACTIVE_BPW, TOKEN_NILW, TPS, information-rate, bytes/token are derived.
- Active subset must satisfy 0 < ACTIVE < TOTAL.
- Reuse requires both REUSE_EVENTS > 0 and REUSED_BITS > 0.
- Exact accounting is required.
- Arithmetic overflow or zero-divide => FAIL.
- Scheduler authority is untouched.

Build from an x64 Native Tools Command Prompt:

    build_masm.bat

The zero witness harness must exit 0 only when authorization stays false.
