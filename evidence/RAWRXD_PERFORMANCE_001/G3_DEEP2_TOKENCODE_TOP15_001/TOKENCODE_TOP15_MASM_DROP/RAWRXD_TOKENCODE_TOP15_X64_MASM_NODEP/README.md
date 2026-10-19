# RAWRXD_TOKENCODE_TOP15_X64_MASM_NODEP

Pure x64 MASM source drop for the encode side of the runtime generator.

`tokencode_authorized` is derived internally from raw encode/runtime counters.
The caller cannot provide witness states or final authorization.

Authority chain:

    RAW TOKEN ENCODE COUNTERS
              |
              v
         TE01..TE14
              |
              v
       TE15 CONJUNCTION
              |
              v
     TOKENCODE_AUTHORIZED

Build from an x64 Native Tools Command Prompt:

    build_masm.bat

Expected:

    TOKENCODE_TOP15_X64_MASM_TESTS=PASS

Harnesses:
- zero: NOT_RUN cannot authorize
- positive: exact 128-token encode closure
- tamper: tokencode=127 with generated=128 fails TE04
