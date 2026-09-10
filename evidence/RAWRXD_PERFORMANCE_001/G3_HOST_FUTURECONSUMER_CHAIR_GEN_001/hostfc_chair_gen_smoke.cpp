/* hostfc_prefetch_smoke.cpp — purified HOST_DECODE edge; no Vulkan. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "HostFutureConsumerPrefetch.hpp"
#include <cstdio>
#include <cstring>

static HANDLE gFile = INVALID_HANDLE_VALUE;
static HANDLE gMap = nullptr;
static void* gView = nullptr;

static void* MapPref(uint64_t off, size_t n) {
    if (!gView || n == 0 || off + n > 65536ull) return nullptr;
    return static_cast<uint8_t*>(gView) + static_cast<size_t>(off);
}

int main() {
    wchar_t path[MAX_PATH];
    GetTempPathW(MAX_PATH, path);
    wcscat_s(path, L"hostfc_prefetch.bin");
    gFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (gFile == INVALID_HANDLE_VALUE) return 2;
    char buf[4096];
    std::memset(buf, 0xA5, sizeof(buf));
    DWORD wr = 0;
    for (int i = 0; i < 16; ++i) WriteFile(gFile, buf, sizeof(buf), &wr, nullptr);
    gMap = CreateFileMappingW(gFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    gView = gMap ? MapViewOfFile(gMap, FILE_MAP_READ, 0, 0, 65536) : nullptr;
    if (!gView) return 3;

    _putenv_s("RAWRXD_HOST_DECODE", "1");
    Deep2::hostfc::ArmFromProductRun(4);
    Deep2::hostfc::BindMapPrefetch(MapPref);
    Deep2::hostfc::BindHostWeight(gView, 4096, 0);
    {
        Deep2::hostfc::LayerEdge e(0, 4);
        volatile unsigned sink = 0;
        for (int i = 0; i < 100000; ++i) sink += (unsigned)i;
        (void)sink;
    }
    Deep2::hostfc::SealDecode(0, stdout);
    if (gView) UnmapViewOfFile(gView);
    if (gMap) CloseHandle(gMap);
    CloseHandle(gFile);
    DeleteFileW(path);
    return 0;
}
