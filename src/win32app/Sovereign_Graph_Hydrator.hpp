// Sovereign_Graph_Hydrator.hpp - Zero-Copy Binary Manifest Loader
#pragma once
#include <windows.h>
#include <cstdint>

#pragma pack(push, 1)
struct XR_Node_Manifest {
    uint64_t kernel_ptr;
    uint64_t deadline_cycles;
    uint32_t state;
    uint32_t flags;
    uint64_t output_ptr;
    uint64_t input_ptr;
};
#pragma pack(pop)

class SovereignGraphHydrator {
private:
    HANDLE hFile;
    HANDLE hMap;
    uintptr_t pMappedData;

public:
    SovereignGraphHydrator() : hFile(INVALID_HANDLE_VALUE), hMap(NULL), pMappedData(0) {}

    // Direct zero-copy mapping of the binary manifest
    bool Hydrate(const char* manifest_path) {
        hFile = CreateFileA(manifest_path, GENERIC_READ, FILE_SHARE_READ, NULL, 
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMap == NULL) return false;

        pMappedData = (uintptr_t)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

        // Link registry table directly to mapped memory
        // No parsing, no heap allocation, no serialization overhead
        return (pMappedData != 0);
    }

    // Clean up mapping
    ~SovereignGraphHydrator() {
        if (pMappedData) UnmapViewOfFile((LPCVOID)pMappedData);
        if (hMap) CloseHandle(hMap);
        if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    }

    // Direct access to the ABI-compliant struct array
    inline XR_Node_Manifest* GetNode(uint32_t idx) {
        return (XR_Node_Manifest*)(pMappedData + (idx * sizeof(XR_Node_Manifest)));
    }
};