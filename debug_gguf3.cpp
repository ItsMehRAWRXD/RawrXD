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
        CloseHandle(hFile);
        return 1;
    }
    printf("Mapped successfully\n");
    
    // Check basic header
    uint32_t magic = *reinterpret_cast<const uint32_t*>(base);
    if (magic != 0x46554747) { printf("Invalid magic\n"); return 1; }
    
    uint32_t version = *reinterpret_cast<const uint32_t*>(base + 4);
    if (version != 3) { printf("Unsupported version\n"); return 1; }
    
    uint64_t tensorCount = *reinterpret_cast<const uint64_t*>(base + 8);
    uint64_t metadataKvCount = *reinterpret_cast<const uint64_t*>(base + 16);
    printf("Tensor count: %llu, Metadata KV count: %llu\n", tensorCount, metadataKvCount);
    
    const uint8_t* ptr = base + 24;
    size_t size = static_cast<size_t>(sz.QuadPart);
    
    // Debug KV 0 in detail
    for (uint64_t i = 0; i < 1; ++i) {  // Just KV 0
        printf("KV %llu: ptr=%p, base=%p, size=%zu\n", i, ptr, base, size);
        
        if (ptr + 8 > base + size) { printf("ptr+8 > size\n"); return 1; }
        uint64_t keyLen = *reinterpret_cast<const uint64_t*>(ptr);
        printf("  keyLen = %llu\n", keyLen);
        ptr += 8;
        
        if (ptr + keyLen > base + size) { printf("  ptr+keyLen > size\n"); return 1; }
        std::string key(reinterpret_cast<const char*>(ptr), keyLen);
        printf("  key = '%s' (len=%llu)\n", key.c_str(), keyLen);
        ptr += keyLen;
        
        if (ptr + 8 > base + size) { printf("  ptr+8 > size after key\n"); return 1; }
        uint32_t valueType = *reinterpret_cast<const uint32_t*>(ptr);
        printf("  valueType = %u\n", valueType);
        ptr += 4;
        
        if (ptr + 4 > base + size) { printf("  ptr+4 > size after valueType\n"); return 1; }
        ptr += 4;
        
        printf("  After type/len skip, ptr advanced\n");
        
        switch (valueType)
        {
            case 0: case 1: ptr += 1; break;
            case 2: case 3: ptr += 2; break;
            case 4: case 5: case 6: ptr += 4; break;
            case 7: ptr += 1; break;
            case 8: 
            {
                if (ptr + 8 > base + size) { printf("  string: ptr+8 > size\n"); return 1; }
                uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                printf("  string strLen = %llu\n", strLen);
                ptr += 8;
                if (strLen > static_cast<uint64_t>(base + size - ptr)) { printf("  strLen > remaining\n"); return 1; }
                ptr += strLen;
                break;
            }
            case 9: 
            {
                if (ptr + 8 > base + size) { printf("  array: ptr+8 > size\n"); return 1; }
                uint64_t arrLen = *reinterpret_cast<const uint64_t*>(ptr);
                ptr += 8;
                if (ptr + 4 > base + size) { printf("  array: ptr+4 > size\n"); return 1; }
                uint32_t elemType = *reinterpret_cast<const uint32_t*>(ptr);
                ptr += 4;
                uint64_t elemSize = 0;
                switch (elemType) {
                    case 0: case 1: elemSize = 1; break;
                    case 2: case 3: elemSize = 2; break;
                    case 4: case 5: case 6: elemSize = 4; break;
                    case 7: elemSize = 1; break;
                    case 8: 
                        if (ptr + 8 > base + size) { printf("  nested string ptr+8 > size\n"); return 1; }
                        elemSize = 8; ptr += 8;
                        break;
                    case 9: elemSize = 8; break;
                    default: printf("  unknown elemType %u\n", elemType); return 1;
                }
                if (arrLen > static_cast<uint64_t>(base + size - ptr) / elemSize) { printf("  arrLen * elemSize > remaining\n"); return 1; }
                ptr += arrLen * elemSize;
                break;
            }
            default: printf("  unknown valueType %u\n", valueType); return 1;
        }
        printf("  KV parsed OK\n");
    }
    
    return 0;
}