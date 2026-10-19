# RAWRXD_R671_ARG5_RESIDENCY_HARDENING_X64_MASM_NODEP

Hardening overlay for the real-tensor `r671_tensor_acquire` Win64 ABI.

Important result:

`[rsp+98h]` is correct for the exact pasted prologue:
- Win64 fifth arg at entry = `RSP+28h`
- four pushes = `20h`
- local allocation = `50h`
- current offset = `28h + 20h + 50h = 98h`

The bug is making that relationship a magic number and coupling it to a second
mapping path that can diverge from the locked r671 residency manager.

This drop:
- names and compile-time checks the arg5 offset;
- preserves generation across helper calls;
- adds atomic fail-closed residency reservation/release;
- refuses residency cap crossings;
- refuses accounting underflow;
- counts invalid release/bound/accounting faults.

Preferred production integration:
reuse the locked `a00eceb8...` r671 slot/window manager and make the ABI adapter
consume it, rather than keeping a parallel MapViewOfFile ownership implementation.
