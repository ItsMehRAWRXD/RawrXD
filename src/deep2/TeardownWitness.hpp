#pragma once
#include <cstdio>

/* Monotonic teardown witness — decode hot path must not emit these. */
namespace Deep2 {
inline void Td(int n, const char* tag) {
    std::fprintf(stderr, "TD=%02d %s\n", n, tag);
    std::fflush(stderr);
}
} // namespace Deep2
