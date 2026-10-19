
DEEP2_E2E_FINISH_BALANCE_TO_ENDURANCE_NODEP_20260912

No third-party runtime dependencies. The modules use only C99/C++-compatible
fixed-width types and caller-owned state. Product Vulkan, Windows, GGUF, and
model objects stay outside the drop and are supplied through callbacks.

This package continues the E2E ladder after real same-token dual-GPU overlap:

deep2_decode_finish_balance.*
completion-time solver, Q16 costs, EWMA, start-skew correction,
signed finish-tail correction, best-critical-path rollback.
deep2_persistent_decode.*
persistent command/KV lifecycle and N+1 prefetch contract.
deep2_residency_solver.*
allocation-free deterministic GPU0/GPU1/RAM/MMAP planner.
deep2_streamer_live.*
native session lifecycle: open/prefill/decode/emit/reset/reuse/close.
deep2_endurance.*
repeated multi-generation, multi-model fail-closed certification loop.
deep2_e2e_types.h
common live token receipt and authority-safe predicate.
integration_contract.h
exact product binding rules.
LAW.txt
authority invariants. PROMOTE=0 is mandatory until live evidence exists.
Build

MSVC:

build_msvc.bat

Portable syntax/self-test:

cc -std=c99 -O2 selftest.c deep2_decode_finish_balance.c ^
  deep2_persistent_decode.c deep2_residency_solver.c ^
  deep2_streamer_live.c deep2_endurance.c -o selftest
Important

The callbacks in the self-test are synthetic. A self-test PASS proves only that
the state machines and fail-closed invariants behave as intended. It cannot mint
product, bandwidth, TPS, or promotion authority.
