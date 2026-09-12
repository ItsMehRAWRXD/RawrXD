#include "d2_qpc_seal.h"

// No windows.h dependency. These are the x64 ABI-compatible signatures exported by Kernel32.
#if defined(_WIN32)
extern "C" __declspec(dllimport) int __stdcall QueryPerformanceCounter(long long*);
extern "C" __declspec(dllimport) int __stdcall QueryPerformanceFrequency(long long*);

namespace d2qpc {

static bool qpc_now_win32(void*, std::uint64_t* out) noexcept {
    if (!out) return false;
    long long v=0;
    if (!QueryPerformanceCounter(&v) || v<=0) return false;
    *out=static_cast<std::uint64_t>(v);
    return true;
}
static bool qpc_frequency_win32(void*, std::uint64_t* out) noexcept {
    if (!out) return false;
    long long v=0;
    if (!QueryPerformanceFrequency(&v) || v<=0) return false;
    *out=static_cast<std::uint64_t>(v);
    return true;
}
bool bind_win32_qpc(QpcProvider* out) noexcept {
    if (!out) return false;
    out->user=nullptr;
    out->now=&qpc_now_win32;
    out->frequency=&qpc_frequency_win32;
    return true;
}

} // namespace d2qpc
#else
namespace d2qpc {
bool bind_win32_qpc(QpcProvider*) noexcept { return false; }
}
#endif
