// RKC.h — C ABI for MASM / ScreenPilot
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Begin a goal from UTF-8 query. modelPath may be null/empty.
// Returns 1 on success.
int RKC_BeginGoal(const char* queryUtf8, const char* modelPathUtf8);

// Optional: set hardware budgets (bytes). Call after BeginGoal.
void RKC_SetHardware(unsigned long long vram, unsigned long long weights,
                     unsigned long long kv, unsigned long long arena,
                     unsigned long long margin);

// Resolve world + recipes + gaps. Returns 1 on success.
int RKC_Resolve(void);

// Emit proof state into caller buffer. Returns bytes written (excl NUL),
// or -1 if buffer too small (still writes truncated + NUL if cap>0).
int RKC_EmitState(char* out, size_t cap);

// Optional Require / Reconstruct / Verify (thin C ABI)
void RKC_Require(const char* keyUtf8);
int RKC_Reconstruct(void);
int RKC_Verify(void);

// Returns 1 if SYNTHETIC→REAL is rejected (epistemic safety).
int RKC_VerifyNoSyntheticToReal(void);

#ifdef __cplusplus
}
#endif
