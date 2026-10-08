#include <windows.h>
#include <cstdio>
#include <cstdint>

int main() {
    const char* path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        return 1;
    }
    
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz)) {
        printf("GetFileSizeEx failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    
    printf("File size: %llu bytes\n", sz.QuadPart);
    
    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        printf("CreateFileMapping failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    
    const uint8_t* base = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!base) {
        printf("MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return 1;
    }
    
    printf("Mapped successfully\n");
    
    // Check magic
    uint32_t magic = *reinterpret_cast<const uint32_t*>(base);
    printf("Magic: 0x%08x\n", magic);
    
    // Check version
    uint32_t version = *reinterpret_cast<const uint32_t*>(base + 4);
    printf("Version: %u\n", version);
    
    uint64_t tensorCount = *reinterpret_cast<const uint64_t*>(base + 8);
    printf("Tensor count: %llu\n", tensorCount);
    
    uint64_t metadataKvCount = *reinterpret_cast<const uint64_t*>(base + 16);
    printf("Metadata KV count: %llu\n", metadataKvCount);
    
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}