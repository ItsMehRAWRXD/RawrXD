/* TG3-G2 Debug Version */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

int main(int argc, char **argv) {
    printf("TG3-G2 Debug: Starting...\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    
    const char *model_path = argv[1];
    printf("TG3-G2 Debug: Opening %s\n", model_path);
    
    HANDLE hFile = CreateFileA(model_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[FAIL] CreateFileA failed: %lu\n", GetLastError());
        return 1;
    }
    printf("TG3-G2 Debug: File opened\n");
    
    LARGE_INTEGER size;
    GetFileSizeEx(hFile, &size);
    printf("TG3-G2 Debug: File size: %llu bytes\n", size.QuadPart);
    
    printf("TG3-G2 Debug: Creating file mapping...\n");
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        printf("[FAIL] CreateFileMappingA failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    printf("TG3-G2 Debug: File mapping created\n");
    
    printf("TG3-G2 Debug: Mapping view...\n");
    uint8_t *mapped = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    if (!mapped) {
        printf("[FAIL] MapViewOfFile failed: %lu\n", GetLastError());
        return 1;
    }
    printf("TG3-G2 Debug: View mapped at %p\n", mapped);
    
    printf("TG3-G2 Debug: Checking magic...\n");
    if (memcmp(mapped, "GGUF", 4) != 0) {
        printf("[FAIL] Not a GGUF file\n");
        UnmapViewOfFile(mapped);
        return 1;
    }
    printf("TG3-G2 Debug: Magic OK (GGUF)\n");
    
    uint32_t version = *(uint32_t*)(mapped + 4);
    uint64_t n_tensors = *(uint64_t*)(mapped + 8);
    uint64_t n_kv = *(uint64_t*)(mapped + 16);
    
    printf("TG3-G2 Debug: Version: %u\n", version);
    printf("TG3-G2 Debug: Tensors: %llu\n", n_tensors);
    printf("TG3-G2 Debug: KV pairs: %llu\n", n_kv);
    
    printf("TG3-G2 Debug: SUCCESS\n");
    UnmapViewOfFile(mapped);
    return 0;
}
