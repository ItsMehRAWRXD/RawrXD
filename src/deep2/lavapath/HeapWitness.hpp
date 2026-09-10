/* HeapWitness.hpp — process-heap integrity checkpoints (diagnostic only). */
#pragma once
#include <cstdio>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace heap {

inline int ValidateProcessHeap() {
#ifdef _WIN32
    return ::HeapValidate(::GetProcessHeap(), 0, nullptr) ? 1 : 0;
#else
    return 1;
#endif
}

/* Emit HEAP_OK_<tag>=0|1. Returns ok. No behavioral change. */
inline int EmitOk(FILE* f, const char* tag) {
    if (!f) f = stderr;
    const int ok = ValidateProcessHeap();
    std::fprintf(f, "HEAP_OK_%s=%d\n", tag, ok);
    std::fflush(f);
    return ok;
}

} // namespace heap
} // namespace Deep2
