#pragma once

// Keep one canonical C ABI declaration for both architecture backends.
// In particular, do not redeclare the x64 entry point with a different return
// type: that conflicts with brutal_gzip.h when both headers are included.
#include "brutal_gzip.h"

#ifdef _WIN64
#  define HAS_BRUTAL_GZIP_MASM 1
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#  define HAS_BRUTAL_GZIP_NEON 1
#endif
