#pragma once

// Keep one canonical C ABI declaration for both architecture backends.
// Backend feature macros are exported by the CMake target that actually links
// the corresponding implementation; CPU architecture alone does not prove
// that the symbol is present in the final link.
#include "brutal_gzip.h"

#if defined(RAWRXD_HAVE_BRUTAL_GZIP_MASM)
#  define HAS_BRUTAL_GZIP_MASM 1
#endif

#if defined(RAWRXD_HAVE_BRUTAL_GZIP_NEON)
#  define HAS_BRUTAL_GZIP_NEON 1
#endif
