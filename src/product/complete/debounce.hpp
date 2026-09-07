#pragma once
#include <cstdint>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::product {

struct Debounce {
    uint32_t delayMs = 80;
    DWORD lastTick = 0;
    bool arm() {
#ifdef _WIN32
        lastTick = GetTickCount();
#endif
        return true;
    }
    bool ready() const {
#ifdef _WIN32
        return (GetTickCount() - lastTick) >= delayMs;
#else
        return true;
#endif
    }
};

} // namespace rawr::product
