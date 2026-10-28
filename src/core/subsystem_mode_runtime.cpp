// ============================================================================
// subsystem_mode_runtime.cpp — DORMANT (B07). Empty void asm_* / Mode* would
// shadow MagBuf / omega / subsystem_api if linked into Win32IDE.
// Mode* + SO_*/AD_* owners: rawrxd_subsystem_api.cpp (GATED fail-closed).
// LAW: evidence/BLOCKER_CLEAR_015_001/LAW_INTENTIONAL_STRIPS.txt
// ============================================================================
#error "subsystem_mode_runtime.cpp is CMake-omitted; empty asm_* must not link. See BLOCKER_CLEAR_015_001 B07."
