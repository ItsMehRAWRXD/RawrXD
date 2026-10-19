# RAWRXD_AUTHORITATIVE_RUNTIME_DECODE_X64_MASM_NODEP

Pure x64 MASM, source-only, no third-party dependencies.

Purpose:
Derive live decode authority from raw runtime counters only.

Authority chain:

    RAW_DECODE_COUNTERS
          |
          v
    MASM DERIVED D01..D14
          |
          v
    D15 = conjunction reporter
          |
          v
    DECODE_AUTHORIZED

No caller-supplied PASS states are accepted.

This module:
- does not issue N+1;
- does not call pumpOnce / Ensure* / forwardLayer;
- does not submit GPU work;
- does not set SCOREBOARD_SCHEDULER_LIVE;
- does not set PROMOTE;
- does not set NILW authorization.

Build:
    build_masm.bat

Additional decode-authority law:
- PATH_MIXED never authorizes; host/GPU authority must be singular for this witness.
