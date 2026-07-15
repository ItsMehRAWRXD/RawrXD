/* tg002_raw.c - Raw byte inspection */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file.gguf>\n", argv[0]);
        return 1;
    }
    
    HANDLE h = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Failed to open\n");
        return 1;
    }
    
    LARGE_INTEGER size;
    GetFileSizeEx(h, &size);
    
    HANDLE map = CreateFileMappingA(h, NULL, PAGE_READONLY, 0, 0, NULL);
    uint8_t* data = (uint8_t*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    
    printf("Bytes 56-80 (0x38-0x50):\n");
    for (int i = 56; i < 80; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
    printf("\nAs uint64 at 56: %llu\n", 
           (unsigned long long)(*(uint64_t*)(data + 56)));
    printf("As uint64 at 64: %llu\n", 
           (unsigned long long)(*(uint64_t*)(data + 64)));
    
    printf("\nAs string at 64: \"");
    for (int i = 64; i < 80; i++) {
        if (data[i] >= 32 && data[i] < 127) printf("%c", data[i]);
        else printf(".");
    }
    printf("\"\n");
    
    UnmapViewOfFile(data);
    CloseHandle(map);
    CloseHandle(h);
    
    return 0;
}
