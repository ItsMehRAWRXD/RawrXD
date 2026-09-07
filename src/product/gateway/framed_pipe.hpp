#pragma once
#include <cstdint>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr::product {

extern "C" void RawrStoreU32(void* dst, uint32_t v);
extern "C" uint32_t RawrLoadU32(const void* src);

inline const char* ProductPipeName() { return "\\\\.\\pipe\\rawrxd_product"; }

#ifdef _WIN32
inline bool FrameWrite(HANDLE h, const std::string& s) {
    uint8_t hdr[4];
    RawrStoreU32(hdr, (uint32_t)s.size());
    DWORD wr = 0;
    if (!WriteFile(h, hdr, 4, &wr, nullptr) || wr != 4) return false;
    if (s.empty()) return true;
    return WriteFile(h, s.data(), (DWORD)s.size(), &wr, nullptr) &&
           wr == (DWORD)s.size();
}

inline bool FrameRead(HANDLE h, std::string& s) {
    uint8_t hdr[4];
    DWORD rd = 0;
    if (!ReadFile(h, hdr, 4, &rd, nullptr) || rd != 4) return false;
    uint32_t n = RawrLoadU32(hdr);
    if (n > (1u << 20)) return false;
    s.assign(n, '\0');
    if (!n) return true;
    return ReadFile(h, s.data(), n, &rd, nullptr) && rd == n;
}

inline bool ProductClientCall(const char* pipe, const std::string& req,
                              std::string& rsp, DWORD waitMs = 2000) {
    WaitNamedPipeA(pipe, waitMs);
    HANDLE h = CreateFileA(pipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = FrameWrite(h, req) && FrameRead(h, rsp);
    CloseHandle(h);
    return ok;
}
#endif

} // namespace rawr::product
