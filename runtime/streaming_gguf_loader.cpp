// ============================================================================
// Streaming GGUF Loader v2 Implementation
// ============================================================================
// Based on forensics tool logic - memory-mapped, robust parsing
// ============================================================================

#include "streaming_gguf_loader.hpp"
#include <iostream>
#include <cstring>

namespace RawrXD {
namespace Runtime {

StreamingGGUFLoader::StreamingGGUFLoader() = default;

StreamingGGUFLoader::~StreamingGGUFLoader() {
    Close();
}

bool StreamingGGUFLoader::Open(const std::string& path) {
    Close();

#ifdef _WIN32
    // Windows: Open file
    m_hFile = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (m_hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[StreamingGGUF] Failed to open file: " << path << std::endl;
        return false;
    }

    // Get file size
    LARGE_INTEGER size;
    if (!GetFileSizeEx(m_hFile, &size)) {
        Close();
        return false;
    }
    m_fileSize = static_cast<size_t>(size.QuadPart);

    // Create file mapping
    m_hMapping = CreateFileMapping(m_hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m_hMapping) {
        Close();
        return false;
    }

    // Map view
    m_data = MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!m_data) {
        Close();
        return false;
    }
#else
    // POSIX: Open and mmap
    m_fd = open(path.c_str(), O_RDONLY);
    if (m_fd < 0) {
        return false;
    }

    struct stat st;
    if (fstat(m_fd, &st) < 0) {
        Close();
        return false;
    }
    m_fileSize = st.st_size;

    m_data = mmap(nullptr, m_fileSize, PROT_READ, MAP_PRIVATE, m_fd, 0);
    if (m_data == MAP_FAILED) {
        Close();
        return false;
    }
#endif

    // Parse the file
    uint8_t* pos = static_cast<uint8_t*>(m_data);

    if (!ParseHeader(pos)) {
        Close();
        return false;
    }

    if (!SkipMetadata(pos)) {
        Close();
        return false;
    }

    // Parse all tensor info
    for (uint64_t i = 0; i < m_tensorCount; i++) {
        if (!ParseTensorInfo(pos)) {
            Close();
            return false;
        }
    }

    // Calculate tensor data offset (aligned to 64 bytes)
    m_tensorDataOffset = (reinterpret_cast<uintptr_t>(pos) - reinterpret_cast<uintptr_t>(m_data) + 63) & ~63ULL;

    m_isOpen = true;
    return true;
}

void StreamingGGUFLoader::Close() {
    m_tensors.clear();
    m_isOpen = false;

#ifdef _WIN32
    if (m_data) {
        UnmapViewOfFile(m_data);
        m_data = nullptr;
    }
    if (m_hMapping) {
        CloseHandle(m_hMapping);
        m_hMapping = nullptr;
    }
    if (m_hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
#else
    if (m_data && m_data != MAP_FAILED) {
        munmap(m_data, m_fileSize);
        m_data = nullptr;
    }
    if (m_fd >= 0) {
        close(m_fd);
        m_fd = -1;
    }
#endif

    m_fileSize = 0;
    m_version = 0;
    m_tensorCount = 0;
    m_metadataCount = 0;
    m_tensorDataOffset = 0;
}

bool StreamingGGUFLoader::ParseHeader(uint8_t*& pos) {
    if (m_fileSize < 24) {
        std::cerr << "[StreamingGGUF] File too small for header" << std::endl;
        return false;
    }

    // Check magic
    uint32_t magic = *reinterpret_cast<uint32_t*>(pos);
    pos += 4;

    if (magic != GGUF_MAGIC) {
        std::cerr << "[StreamingGGUF] Invalid magic: 0x" << std::hex << magic << std::dec << std::endl;
        return false;
    }

    // Version
    m_version = *reinterpret_cast<uint32_t*>(pos);
    pos += 4;

    if (m_version != 3) {
        std::cerr << "[StreamingGGUF] Unsupported version: " << m_version << std::endl;
        return false;
    }

    // Tensor count
    m_tensorCount = *reinterpret_cast<uint64_t*>(pos);
    pos += 8;

    // Metadata count
    m_metadataCount = *reinterpret_cast<uint64_t*>(pos);
    pos += 8;

    return true;
}

bool StreamingGGUFLoader::SkipMetadata(uint8_t*& pos) {
    uint8_t* end = static_cast<uint8_t*>(m_data) + m_fileSize;

    for (uint64_t i = 0; i < m_metadataCount; i++) {
        // Key length
        if (pos + 8 > end) return false;
        uint64_t keyLen = *reinterpret_cast<uint64_t*>(pos);
        pos += 8;

        // Skip key
        if (pos + keyLen > end) return false;
        pos += keyLen;

        // Value type
        if (pos + 4 > end) return false;
        uint32_t valType = *reinterpret_cast<uint32_t*>(pos);
        pos += 4;

        // Skip value
        if (!SkipMetadataValue(pos, valType)) return false;
    }

    return true;
}

bool StreamingGGUFLoader::SkipMetadataValue(uint8_t*& pos, uint32_t type) {
    uint8_t* end = static_cast<uint8_t*>(m_data) + m_fileSize;

    switch (type) {
        case 0: case 1: case 7: // UINT8, INT8, BOOL
            if (pos + 1 > end) return false;
            pos += 1;
            return true;
        case 2: case 3: // UINT16, INT16
            if (pos + 2 > end) return false;
            pos += 2;
            return true;
        case 4: case 5: case 6: // UINT32, INT32, FLOAT32
            if (pos + 4 > end) return false;
            pos += 4;
            return true;
        case 8: { // STRING
            if (pos + 8 > end) return false;
            uint64_t len = *reinterpret_cast<uint64_t*>(pos);
            pos += 8;
            if (pos + len > end) return false;
            pos += len;
            return true;
        }
        case 9: { // ARRAY
            if (pos + 4 > end) return false;
            uint32_t elemType = *reinterpret_cast<uint32_t*>(pos);
            pos += 4;
            if (pos + 8 > end) return false;
            uint64_t arrLen = *reinterpret_cast<uint64_t*>(pos);
            pos += 8;
            for (uint64_t j = 0; j < arrLen; j++) {
                if (!SkipMetadataValue(pos, elemType)) return false;
            }
            return true;
        }
        case 10: case 11: case 12: // UINT64, INT64, FLOAT64
            if (pos + 8 > end) return false;
            pos += 8;
            return true;
        default:
            // Unknown type, skip 8 bytes
            if (pos + 8 > end) return false;
            pos += 8;
            return true;
    }
}

bool StreamingGGUFLoader::ParseTensorInfo(uint8_t*& pos) {
    uint8_t* end = static_cast<uint8_t*>(m_data) + m_fileSize;

    TensorInfo info;

    // Name length
    if (pos + 8 > end) return false;
    uint64_t nameLen = *reinterpret_cast<uint64_t*>(pos);
    pos += 8;

    // Name
    if (pos + nameLen > end) return false;
    info.name = std::string(reinterpret_cast<char*>(pos), nameLen);
    pos += nameLen;

    // Dimensions count
    if (pos + 4 > end) return false;
    uint32_t nDims = *reinterpret_cast<uint32_t*>(pos);
    pos += 4;

    // Dimensions
    uint64_t numElements = 1;
    for (uint32_t i = 0; i < nDims; i++) {
        if (pos + 8 > end) return false;
        uint64_t dim = *reinterpret_cast<uint64_t*>(pos);
        pos += 8;
        info.shape.push_back(dim);
        numElements *= dim;
    }

    // Type
    if (pos + 4 > end) return false;
    info.type = *reinterpret_cast<uint32_t*>(pos);
    pos += 4;

    // Offset
    if (pos + 8 > end) return false;
    info.offset = *reinterpret_cast<uint64_t*>(pos);
    pos += 8;

    // Calculate size
    info.size = CalculateTensorSize(info.type, numElements);

    // Store
    m_tensors[info.name] = info;

    return true;
}

uint64_t StreamingGGUFLoader::CalculateTensorSize(uint32_t type, uint64_t numElements) const {
    switch (type) {
        case 0: return numElements * 4;           // F32
        case 1: return numElements * 2;           // F16
        case 2: return ((numElements + 31) / 32) * 18;  // Q4_0
        case 3: return ((numElements + 31) / 32) * 20;  // Q4_1
        case 8: return ((numElements + 31) / 32) * 34;  // Q8_0
        case 10: return ((numElements + 255) / 256) * 84;  // Q2_K
        case 12: return ((numElements + 255) / 256) * 144; // Q4_K
        case 14: return ((numElements + 255) / 256) * 210; // Q6_K
        default: return numElements * 4;          // Default to F32
    }
}

bool StreamingGGUFLoader::GetTensor(const std::string& name, TensorInfo& info) const {
    auto it = m_tensors.find(name);
    if (it == m_tensors.end()) return false;
    info = it->second;
    return true;
}

const uint8_t* StreamingGGUFLoader::GetTensorData(const TensorInfo& info) const {
    if (!m_data) return nullptr;
    return static_cast<const uint8_t*>(m_data) + m_tensorDataOffset + info.offset;
}

std::vector<std::string> StreamingGGUFLoader::GetTensorNames() const {
    std::vector<std::string> names;
    for (const auto& [name, _] : m_tensors) {
        names.push_back(name);
    }
    return names;
}

// TensorInfo helper implementations
uint64_t TensorInfo::NumElements() const {
    uint64_t num = 1;
    for (auto dim : shape) {
        num *= dim;
    }
    return num;
}

uint64_t TensorInfo::ByteSize() const {
    return size;
}

// Create TensorView from tensor info
TensorView StreamingGGUFLoader::CreateTensorView(const TensorInfo& info) const {
    TensorView::MmapInfo mmapInfo;
    mmapInfo.base = m_data;
    mmapInfo.fileOffset = m_tensorDataOffset;
    mmapInfo.tensorOffset = info.offset;
    mmapInfo.dataSize = info.size;
    mmapInfo.type = static_cast<GGMLType>(info.type);
    mmapInfo.shape = info.shape;
    return TensorView(mmapInfo);
}

// Metadata storage for lookup
static std::unordered_map<std::string, int64_t> s_metadataInt;
static std::unordered_map<std::string, std::string> s_metadataString;

int64_t StreamingGGUFLoader::GetMetadataInt(const std::string& key, int64_t defaultValue) const {
    auto it = s_metadataInt.find(key);
    if (it != s_metadataInt.end()) return it->second;
    return defaultValue;
}

std::string StreamingGGUFLoader::GetMetadataString(const std::string& key, const std::string& defaultValue) const {
    auto it = s_metadataString.find(key);
    if (it != s_metadataString.end()) return it->second;
    return defaultValue;
}

void StreamingGGUFLoader::StoreMetadata(const std::string& key, int64_t value) {
    s_metadataInt[key] = value;
}

void StreamingGGUFLoader::StoreMetadata(const std::string& key, const std::string& value) {
    s_metadataString[key] = value;
}

} // namespace Runtime
} // namespace RawrXD
