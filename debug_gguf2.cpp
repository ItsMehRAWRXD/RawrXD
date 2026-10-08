#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

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
    
    // Skip metadata
    for (uint64_t i = 0; i < 45; ++i) {  // metadataKvCount = 45 from earlier debug
        if (ptr + 8 > base + size) { printf("KV %llu: ptr+8 > size\n", i); return 1; }
        uint64_t keyLen = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        if (ptr + keyLen > base + size) { printf("KV %llu: ptr+keyLen > size\n", i); return 1; }
        ptr += keyLen;
        
        if (ptr + 8 > base + size) { printf("KV %llu: ptr+8 > size after key\n", i); return 1; }
        uint32_t valueType = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        if (ptr + 4 > base + size) { printf("KV %llu: ptr+4 > size after valueType\n", i); return 1; }
        ptr += 4;
        
        switch (valueType)
        {
            case 0: case 1: ptr += 1; break;
            case 2: case 3: ptr += 2; break;
            case 4: case 5: case 6: ptr += 4; break;
            case 7: ptr += 1; break;
            case 8: 
            {
                if (ptr + 8 > base + size) { printf("KV %llu: string ptr+8 > size\n", i); return 1; }
                uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                ptr += 8;
                if (strLen > static_cast<uint64_t>(base + size - ptr)) { printf("KV %llu: strLen > remaining\n", i); return 1; }
                ptr += strLen;
                break;
            }
            case 9: 
            {
                if (ptr + 8 > base + size) { printf("KV %llu: array ptr+8 > size\n", i); return 1; }
                uint64_t arrLen = *reinterpret_cast<const uint64_t*>(ptr);
                ptr += 8;
                if (ptr + 4 > base + size) { printf("KV %llu: array ptr+4 > size\n", i); return 1; }
                uint32_t elemType = *reinterpret_cast<const uint32_t*>(ptr);
                ptr += 4;
                uint64_t elemSize = 0;
                switch (elemType) {
                    case 0: case 1: elemSize = 1; break;
                    case 2: case 3: elemSize = 2; break;
                    case 4: case 5: case 6: elemSize = 4; break;
                    case 7: elemSize = 1; break;
                    case 8: 
                        if (ptr + 8 > base + size) { printf("KV %llu: nested string ptr+8 > size\n", i); return 1; }
                        elemSize = 8; ptr += 8;
                        break;
                    case 9: elemSize = 8; break;
                    default: printf("KV %llu: unknown elemType %u\n", i, elemType); return 1;
                }
                if (arrLen > static_cast<uint64_t>(base + size - ptr) / elemSize) { printf("KV %llu: arrLen * elemSize > remaining\n", i); return 1; }
                ptr += arrLen * elemSize;
                break;
            }
            default: printf("KV %llu: unknown valueType %u\n", i, valueType); return 1;
        }
        printf("KV %llu parsed OK, ptr advanced\n", i);
    }
    
    printf("All metadata KVs parsed successfully\n");
    
    // Now try to parse tensor info
    for (uint64_t i = 0; i < 377; ++i)
    {
        if (ptr + 8 > base + size) { printf("Tensor %llu: ptr+8 > size\n", i); return 1; }
        uint64_t nameLen = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        if (ptr + nameLen > base + size) { printf("Tensor %llu: ptr+nameLen > size\n", i); return 1; }
        ptr += nameLen;
        
        if (ptr + 4 + 8 > base + size) { printf("Tensor %llu: ptr+4+8 > size\n", i); return 1; }
        uint32_t nDims = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        uint32_t ggmlType = *reinterpret_cast<const uint32_t*>(ptr);
        ptr += 4;
        
        for (uint32_t d = 0; d < nDims; ++d) {
            if (ptr + 8 > base + size) { printf("Tensor %llu dim %u: ptr+8 > size\n", i, d); return 1; }
            ptr += 8;
        }
        
        uint64_t offset = *reinterpret_cast<const uint64_t*>(ptr);
        ptr += 8;
        
        if (i < 5) {
            printf("Tensor %llu: nDims=%u, type=%u, offset=%llu\n", i, nDims, ggmlType, offset);
        }
    }
    
    printf("All tensors parsed successfully!\n");
    
    return 0;
}