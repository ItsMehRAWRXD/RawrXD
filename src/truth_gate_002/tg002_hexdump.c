/* tg002_hexdump.c - Hex dump the GGUF header */
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
        printf("Failed to open file\n");
        return 1;
    }
    
    /* Read first 256 bytes */
    uint8_t buf[256];
    DWORD read;
    ReadFile(h, buf, 256, &read, NULL);
    CloseHandle(h);
    
    printf("First %lu bytes:\n", read);
    printf("Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |  ASCII\n");
    printf("----------------------------------------------------------------\n");
    
    for (int i = 0; i < 256; i += 16) {
        printf("%04X  ", i);
        for (int j = 0; j < 16 && i + j < 256; j++) {
            printf("%02X ", buf[i + j]);
        }
        printf(" | ");
        for (int j = 0; j < 16 && i + j < 256; j++) {
            uint8_t c = buf[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
    
    /* Parse header manually */
    printf("\n=== Header Parsing ===\n");
    uint32_t magic = *(uint32_t*)buf;
    printf("Magic: 0x%08X (GGUF = 0x46554747)\n", magic);
    
    uint32_t version = *(uint32_t*)(buf + 4);
    printf("Version: %u\n", version);
    
    uint64_t tensor_count = *(uint64_t*)(buf + 8);
    printf("Tensor count: %llu\n", (unsigned long long)tensor_count);
    
    uint64_t metadata_count = *(uint64_t*)(buf + 16);
    printf("Metadata count: %llu\n", (unsigned long long)metadata_count);
    
    /* Parse first metadata entry */
    printf("\n=== First Metadata Entry (at offset 24) ===\n");
    uint8_t* p = buf + 24;
    
    uint64_t key_len = *(uint64_t*)p;
    printf("Key length: %llu\n", (unsigned long long)key_len);
    p += 8;
    
    if (key_len < 100) {
        printf("Key: \"");
        for (uint64_t i = 0; i < key_len; i++) {
            printf("%c", p[i]);
        }
        printf("\"\n");
    }
    p += key_len;
    
    uint32_t val_type = *(uint32_t*)p;
    printf("Value type: %u\n", val_type);
    p += 4;
    
    printf("\nRaw bytes at offset 24:\n");
    for (int i = 0; i < 64; i++) {
        printf("%02X ", buf[24 + i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
    return 0;
}
