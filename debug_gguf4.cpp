#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>

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
    
    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        printf("CreateFileMapping failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    
    const uint8_t* base = static_cast<const uint8_t*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!base) {
        printf("MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    
    // Dump first 200 bytes after header (offset 24)
    printf("First 200 bytes after header (offset 24):\n");
    for (int i = 0; i < 200; i++) {
        if (i % 16 == 0) printf("\n%04x: ", i);
        printf("%02x ", base[24 + i]);
    }
    printf("\n\n");
    
    // Also check at offset 56 (where string length should be for KV 0)
    printf("Bytes at offset 56-63 (string length for KV 0):\n");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", base[56 + i]);
    }
    printf("\n");
    
    // Parse first KV manually
    const uint8_t* ptr = base + 24;
    uint64_t keyLen = *reinterpret_cast<const uint64_t*>(base + 24);
    printf("keyLen = %llu\n", keyLen);
    
    const uint8_t* keyStart = base + 32;
    char key[21] = {0};
    memcpy(key, base + 32, 20);
    printf("Key: '%s'\n", key);
    
    uint32_t valueType = *reinterpret_cast<const uint32_t*>(base + 52);
    printf("valueType = %u\n", *reinterpret_cast<const uint32_t*>(base + 52));
    
    uint64_t strLen = *reinterpret_cast<const uint64_t*>(base + 56);
    printf("String length at offset 56: %llu (0x%llx)\n", strLen, strLen);
    
    // Check what the actual string length should be
    printf("Expected string length for 'DeepSeek' = 8\n");
    printf("Bytes at offset 56-63: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", base[56 + i]);
    }
    printf("\n");
    
    // Also check the bytes around offset 56
    printf("\nBytes at offset 50-70:\n");
    for (int i = 0; i < 20; i++) {
        printf("%02x ", base[50 + i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    printf("\n");
    
    return 0;
}