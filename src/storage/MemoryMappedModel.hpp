// src/storage/MemoryMappedModel.hpp
// Win32 File-View Lifecycle Container — Zero-copy virtual memory mapping
#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <iostream>

class MemoryMappedModel {
private:
    HANDLE m_hFile;
    HANDLE m_hFileMapping;
    void* m_pBaseAddress;
    uint64_t m_fileSize;
    bool m_isMapped;

public:
    MemoryMappedModel();
    ~MemoryMappedModel();

    bool MapModelToVirtualSpace(const std::wstring& filePath);
    void UnmapModel();

    const void* GetBaseAddress() const { return m_pBaseAddress; }
    uint64_t GetFileSize() const { return m_fileSize; }
    bool IsMapped() const { return m_isMapped; }

    // Read a specific tensor memory block safely via pointer calculation offsets
    const void* ResolveTensorSlice(uint64_t relativeOffset) const {
        if (!m_pBaseAddress) return nullptr;
        return static_cast<const void*>(
            static_cast<const uint8_t*>(m_pBaseAddress) + relativeOffset);
    }
};
