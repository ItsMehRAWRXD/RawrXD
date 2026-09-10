#pragma once
/* PE IMAGE_FILE_LARGE_ADDRESS_AWARE probe — amdvlk snmalloc needs LAA. */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

inline int ProcessIsLargeAddressAware() {
#ifdef _WIN32
    HMODULE mod = GetModuleHandleW(nullptr);
    if (!mod) return 0;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<unsigned char*>(mod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return (nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
               ? 1
               : 0;
#else
    return 1;
#endif
}

} // namespace Deep2
