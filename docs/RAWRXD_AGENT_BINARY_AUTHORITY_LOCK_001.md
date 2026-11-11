# RawrXD Agent Binary Authority Lock

This document keeps product certification fail-closed while development builds
continue independently.

```ini
PRODUCT_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
EXPECTED_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
REBUILD_THIS_DISPATCH=0
PROMOTE=0
TIP_CLIMB=HOLD
PRODUCT_CERTIFIED=0
GHOSTTEXT_WITNESS_SHA=B421...
GHOSTTEXT_CERTIFIED=1
GHOSTTEXT_SCOPE=WITNESS_ONLY
ABSORB=NOT_AUTHORIZED
```

## Current verification disposition

The frozen `G:` product path was not reachable from the current execution
environment during the authority check. Therefore TinyLlama/Gemma3 product
tests are `NOT_RUN`; no build-tree executable is an acceptable substitute.

Development artifacts under `F:\rawrxd` remain development-only evidence. They
must not be attributed to the frozen product executable or used to promote the
product tip. The independent GhostText witness remains separate and must not be
absorbed into the product binary without explicit authorization.

Every future product receipt must record the absolute executable path, complete
SHA-256, test/model identity, process ID, exit code, and evidence directory.
