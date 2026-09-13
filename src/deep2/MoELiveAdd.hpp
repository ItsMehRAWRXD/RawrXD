#pragma once
/* MoELiveAdd — relaxed counter add safe across DualStick stick threads. */
#include <cstdint>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

inline void MoELiveAdd(uint64_t& field, uint64_t v) {
    if (!v) return;
#ifdef _WIN32
    ::InterlockedAdd64(reinterpret_cast<volatile LONG64*>(&field),
                       static_cast<LONG64>(v));
#else
    __atomic_fetch_add(&field, v, __ATOMIC_RELAXED);
#endif
}

} // namespace Deep2
