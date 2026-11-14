// dap_peer_pe.hpp — remote PE export resolve (peer DAP_CLI). PROMOTE=0.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace dap_peer {

inline bool ReadRemote(HANDLE p, uint64_t a, void* b, SIZE_T n) {
    SIZE_T got = 0;
    return ReadProcessMemory(p, reinterpret_cast<LPCVOID>(a), b, n, &got) &&
           got == n;
}

inline bool WriteRemote(HANDLE p, uint64_t a, const void* b, SIZE_T n) {
    SIZE_T got = 0;
    DWORD old = 0;
    VirtualProtectEx(p, reinterpret_cast<LPVOID>(a), n, PAGE_EXECUTE_READWRITE,
                     &old);
    const bool ok =
        WriteProcessMemory(p, reinterpret_cast<LPVOID>(a), b, n, &got) &&
        got == n;
    VirtualProtectEx(p, reinterpret_cast<LPVOID>(a), n, old, &old);
    FlushInstructionCache(p, reinterpret_cast<LPCVOID>(a), n);
    return ok;
}

inline bool ResolveExportVa(HANDLE proc, uint64_t imageBase, const char* name,
                            uint64_t* outVa) {
    if (!outVa || !name) return false;
    WORD mz = 0;
    if (!ReadRemote(proc, imageBase, &mz, 2) || mz != 0x5A4D) return false;
    DWORD peOff = 0;
    if (!ReadRemote(proc, imageBase + 0x3C, &peOff, 4)) return false;
    DWORD sig = 0;
    if (!ReadRemote(proc, imageBase + peOff, &sig, 4) || sig != 0x00004550)
        return false;
    WORD magic = 0;
    if (!ReadRemote(proc, imageBase + peOff + 0x18, &magic, 2)) return false;
    const uint64_t dd =
        imageBase + peOff + 0x18 + (magic == 0x20B ? 0x70ull : 0x60ull);
    DWORD expRva = 0;
    if (!ReadRemote(proc, dd, &expRva, 4) || !expRva) return false;
    const uint64_t exp = imageBase + expRva;
    DWORD numNames = 0, namesRva = 0, ordsRva = 0, funcsRva = 0;
    if (!ReadRemote(proc, exp + 0x18, &numNames, 4)) return false;
    if (!ReadRemote(proc, exp + 0x1C, &funcsRva, 4)) return false;
    if (!ReadRemote(proc, exp + 0x20, &namesRva, 4)) return false;
    if (!ReadRemote(proc, exp + 0x24, &ordsRva, 4)) return false;
    for (DWORD i = 0; i < numNames; ++i) {
        DWORD nameRva = 0;
        if (!ReadRemote(proc, imageBase + namesRva + i * 4, &nameRva, 4))
            continue;
        char nm[64]{};
        if (!ReadRemote(proc, imageBase + nameRva, nm, sizeof(nm) - 1)) continue;
        if (std::strcmp(nm, name) != 0) continue;
        WORD ord = 0;
        if (!ReadRemote(proc, imageBase + ordsRva + i * 2, &ord, 2)) return false;
        DWORD funcRva = 0;
        if (!ReadRemote(proc, imageBase + funcsRva + ord * 4, &funcRva, 4))
            return false;
        *outVa = imageBase + funcRva;
        return true;
    }
    return false;
}

}  // namespace dap_peer
