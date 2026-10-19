# RAWRXD_REVERSE_DOUBLELAYER_BYPASS_X64_MASM_NODEP

Pure x64 MASM source drop adding an explicit reverse/bypass authority lane.

The bypass can authorize without the normal six-domain positive-owner
aggregation, but stale-generation state is absolute and non-bypassable.

Bypass authorization requires:
- same generation epoch
- live generation evidence
- generated_tokens > 0
- exact bypass token/decode commit closure
- zero bypass faults
- zero stale-generation faults

`final_authority` is derived internally; it is not a caller field.

Native build:

    build_masm.bat

Expected:

    REVERSE_DOUBLELAYER_BYPASS_X64_MASM_TESTS=PASS
