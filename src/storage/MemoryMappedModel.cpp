// src/storage/MemoryMappedModel.cpp
// Zero-Copy Page Allocation — Win32 Virtual Memory Manager interface
#include "MemoryMappedModel.hpp"

MemoryMappedModel::MemoryMappedModel()
    : m_hFile(INVALID_HANDLE_VALUE)
    , m_hFileMapping(NULL)
    , m_pBaseAddress(nullptr)
    , m_fileSize(0)
    , m_isMapped(false)
{}

MemoryMappedModel::~MemoryMappedModel() {
    UnmapModel();
}

bool MemoryMappedModel::MapModelToVirtualSpace(const std::wstring& filePath) {
    UnmapModel();

    // 1. Open the GGUF binary file handle with sequential read hint
    m_hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );

    if (m_hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[MemoryMappedModel] CreateFileW failed: " << GetLastError() << "\n";
        return false;
    }

    // 2. Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(m_hFile, &fileSize)) {
        std::cerr << "[MemoryMappedModel] GetFileSizeEx failed: " << GetLastError() << "\n";
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return false;
    }
    m_fileSize = static_cast<uint64_t>(fileSize.QuadPart);

    // 3. Create file mapping object (read-only)
    m_hFileMapping = CreateFileMappingW(
        m_hFile,
        NULL,
        PAGE_READONLY,
        0, 0,  // maximum size = file size
        NULL
    );

    if (!m_hFileMapping) {
        std::cerr << "[MemoryMappedModel] CreateFileMappingW failed: " << GetLastError() << "\n";
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return false;
    }

    // 4. Map the entire file into virtual address space
    m_pBaseAddress = MapViewOfFile(
        m_hFileMapping,
        FILE_MAP_READ,
        0, 0, 0  // offset 0, full file
    );

    if (!m_pBaseAddress) {
        std::cerr << "[MemoryMappedModel] MapViewOfFile failed: " << GetLastError() << "\n";
        CloseHandle(m_hFileMapping);
        m_hFileMapping = NULL;
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return false;
    }

    m_isMapped = true;
    std::cout << "[MemoryMappedModel] Mapped " << (m_fileSize / (1024 * 1024))
              << " MB at " << m_pBaseAddress << "\n";
    return true;
}

void MemoryMappedModel::UnmapModel() {
    if (m_pBaseAddress) {
        UnmapViewOfFile(m_pBaseAddress);
        m_pBaseAddress = nullptr;
    }
    if (m_hFileMapping) {
        CloseHandle(m_hFileMapping);
        m_hFileMapping = NULL;
    }
    if (m_hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
    m_isMapped = false;
    m_fileSize = 0;
}
