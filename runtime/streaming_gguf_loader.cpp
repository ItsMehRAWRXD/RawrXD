// ============================================================================
// Streaming GGUF Loader Implementation
// ============================================================================

#include "streaming_gguf_loader.hpp"
#include <fstream>
#include <iostream>
#include <cstring>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// TensorInfo Implementation
// ============================================================================

uint64_t TensorInfo::NumElements() const {
    uint64_t n = 1;
    for (auto dim : shape) n *= dim;
    return n;
}

uint64_t TensorInfo::ByteSize() const {
    // GGML type sizes (simplified)
    switch (type) {
        case 0:  // F32
            return NumElements() * 4;
        case 1:  // F16
            return NumElements() * 2;
        case 2:  // Q4_0
            return ((NumElements() + 31) / 32) * 18;  // 32 elements per 18-byte block
        case 3:  // Q4_1
            return ((NumElements() + 31) / 32) * 20;
        case 8:  // Q8_0
            return ((NumElements() + 31) / 32) * 34;
        case 10: // Q2_K
            return ((NumElements() + 255) / 256) * 84;  // 256 elements per 84-byte block
        case 12: // Q4_K
            return ((NumElements() + 255) / 256) * 144; // 256 elements per 144-byte block
        case 14: // Q6_K
            return ((NumElements() + 255) / 256) * 210;
        default:
            return NumElements() * 4;  // Fallback to F32
    }
}

// ============================================================================
// MmappedTensor Implementation
// ============================================================================

void MmappedTensor::Unmap() {
#ifdef _WIN32
    if (data) {
        UnmapViewOfFile(data);
        data = nullptr;
    }
    if (hMapping) {
        CloseHandle(hMapping);
        hMapping = nullptr;
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        // Don't close file handle here - owned by loader
        hFile = INVALID_HANDLE_VALUE;
    }
#else
    if (data && data != MAP_FAILED) {
        munmap(data, size);
        data = nullptr;
    }
    if (fd >= 0) {
        // Don't close fd here - owned by loader
        fd = -1;
    }
#endif
}

// ============================================================================
// StreamingGGUFLoader Implementation
// ============================================================================

StreamingGGUFLoader::StreamingGGUFLoader() = default;

StreamingGGUFLoader::~StreamingGGUFLoader() {
    Close();
}

bool StreamingGGUFLoader::Open(const std::string& path) {
    if (m_isOpen) {
        Close();
    }
    
    m_path = path;
    
#ifdef _WIN32
    // Windows: Open file for read
    m_hFile = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (m_hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[StreamingGGUF] Failed to open: " << path << std::endl;
        return false;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(m_hFile, &fileSize)) {
        std::cerr << "[StreamingGGUF] Failed to get file size" << std::endl;
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return false;
    }
    m_fileSize = fileSize.QuadPart;
#else
    // POSIX: Open file
    m_fd = ::open(path.c_str(), O_RDONLY);
    if (m_fd < 0) {
        std::cerr << "[StreamingGGUF] Failed to open: " << path << std::endl;
        return false;
    }
    
    // Get file size
    struct stat st;
    if (fstat(m_fd, &st) < 0) {
        std::cerr << "[StreamingGGUF] Failed to get file size" << std::endl;
        ::close(m_fd);
        m_fd = -1;
        return false;
    }
    m_fileSize = st.st_size;
#endif
    
    // Read header
    uint32_t magic;
    if (!ReadAt(0, &magic, sizeof(magic))) {
        std::cerr << "[StreamingGGUF] Failed to read magic" << std::endl;
        Close();
        return false;
    }
    
    if (magic != GGUF_MAGIC) {
        std::cerr << "[StreamingGGUF] Invalid magic: 0x" << std::hex << magic << std::dec << std::endl;
        Close();
        return false;
    }
    
    // Read version
    if (!ReadAt(4, &m_version, sizeof(m_version))) {
        std::cerr << "[StreamingGGUF] Failed to read version" << std::endl;
        Close();
        return false;
    }
    
    if (m_version > GGUF_VERSION) {
        std::cerr << "[StreamingGGUF] Unsupported version: " << m_version << std::endl;
        Close();
        return false;
    }
    
    // Read tensor and metadata counts
    if (!ReadAt(8, &m_tensorCount, sizeof(m_tensorCount))) {
        std::cerr << "[StreamingGGUF] Failed to read tensor count" << std::endl;
        Close();
        return false;
    }
    
    if (!ReadAt(16, &m_metadataCount, sizeof(m_metadataCount))) {
        std::cerr << "[StreamingGGUF] Failed to read metadata count" << std::endl;
        Close();
        return false;
    }
    
    // Skip metadata section to find tensor data offset
    if (!SkipMetadata()) {
        std::cerr << "[StreamingGGUF] Failed to skip metadata" << std::endl;
        Close();
        return false;
    }
    
    // Current offset is start of tensor info section
    // After tensor info comes tensor data
    m_tensorDataOffset = m_iteratorOffset;
    
    // Calculate tensor data offset by parsing all tensor infos
    for (uint64_t i = 0; i < m_tensorCount; ++i) {
        TensorInfo info;
        if (!ParseTensorInfo(info)) {
            std::cerr << "[StreamingGGUF] Failed to parse tensor info " << i << std::endl;
            Close();
            return false;
        }
        m_tensorDataOffset += info.size;
    }
    
    // Reset iterator to beginning of tensor info
    m_iteratorOffset = 24;  // After header
    SkipMetadata();
    m_currentTensor = 0;
    
    // Verify alignment (forensics insight: must be 64-byte aligned)
    if (m_tensorDataOffset % 64 != 0) {
        std::cerr << "[StreamingGGUF] WARNING: Tensor data offset " << m_tensorDataOffset 
                  << " is not 64-byte aligned" << std::endl;
        // Continue anyway - some files may have different alignment
    }
    
    m_isOpen = true;
    std::cout << "[StreamingGGUF] Opened: " << path << std::endl;
    std::cout << "  Version: " << m_version << std::endl;
    std::cout << "  Tensors: " << m_tensorCount << std::endl;
    std::cout << "  Metadata: " << m_metadataCount << std::endl;
    std::cout << "  Tensor data offset: " << m_tensorDataOffset << " (0x" << std::hex << m_tensorDataOffset << std::dec << ")" << std::endl;
    
    return true;
}

void StreamingGGUFLoader::Close() {
    if (!m_isOpen) return;
    
#ifdef _WIN32
    if (m_hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
#else
    if (m_fd >= 0) {
        ::close(m_fd);
        m_fd = -1;
    }
#endif
    
    m_isOpen = false;
    m_hasIndex = false;
    m_nameIndex.clear();
    m_path.clear();
    m_version = 0;
    m_tensorCount = 0;
    m_metadataCount = 0;
    m_currentTensor = 0;
    m_iteratorOffset = 0;
    m_tensorDataOffset = 0;
    m_fileSize = 0;
}

bool StreamingGGUFLoader::NextTensor(TensorInfo& info) {
    if (!m_isOpen || m_currentTensor >= m_tensorCount) {
        return false;
    }
    
    if (!ParseTensorInfo(info)) {
        return false;
    }
    
    m_currentTensor++;
    return true;
}

void StreamingGGUFLoader::ResetIterator() {
    m_currentTensor = 0;
    m_iteratorOffset = 24;  // After header
    SkipMetadata();
}

bool StreamingGGUFLoader::SeekToTensor(const std::string& name, TensorInfo& info) {
    if (!m_hasIndex) {
        if (!BuildIndex()) {
            return false;
        }
    }
    
    auto it = m_nameIndex.find(name);
    if (it == m_nameIndex.end()) {
        return false;
    }
    
    // Seek to tensor info at stored offset
    m_iteratorOffset = it->second;
    return ParseTensorInfo(info);
}

bool StreamingGGUFLoader::BuildIndex() {
    if (m_hasIndex) return true;
    
    ResetIterator();
    
    for (uint64_t i = 0; i < m_tensorCount; ++i) {
        uint64_t tensorOffset = m_iteratorOffset;
        
        TensorInfo info;
        if (!ParseTensorInfo(info)) {
            return false;
        }
        
        m_nameIndex[info.name] = tensorOffset;
    }
    
    m_hasIndex = true;
    ResetIterator();
    
    std::cout << "[StreamingGGUF] Built index with " << m_nameIndex.size() << " tensors" << std::endl;
    return true;
}

MmappedTensor StreamingGGUFLoader::MapTensor(const TensorInfo& info) {
    MmappedTensor result;
    
    if (!m_isOpen) return result;
    
    uint64_t fileOffset = m_tensorDataOffset + info.offset;
    
    // Forensics insight: Verify 64-byte alignment for SIMD efficiency
    if (fileOffset % 64 != 0) {
        std::cerr << "[StreamingGGUF] WARNING: Tensor '" << info.name 
                  << "' at offset " << fileOffset << " is not 64-byte aligned" << std::endl;
        // Continue anyway - will work but may be slower
    }
    
#ifdef _WIN32
    // Windows memory mapping
    result.hFile = m_hFile;
    
    result.hMapping = CreateFileMapping(
        m_hFile,
        nullptr,
        PAGE_READONLY,
        0,
        0,  // Map entire file
        nullptr
    );
    
    if (!result.hMapping) {
        std::cerr << "[StreamingGGUF] CreateFileMapping failed" << std::endl;
        return result;
    }
    
    result.data = MapViewOfFile(
        result.hMapping,
        FILE_MAP_READ,
        (DWORD)(fileOffset >> 32),
        (DWORD)(fileOffset & 0xFFFFFFFF),
        info.size
    );
    
    if (!result.data) {
        std::cerr << "[StreamingGGUF] MapViewOfFile failed" << std::endl;
        CloseHandle(result.hMapping);
        result.hMapping = nullptr;
        return result;
    }
#else
    // POSIX memory mapping
    result.fd = m_fd;
    
    result.data = mmap(
        nullptr,
        info.size,
        PROT_READ,
        MAP_PRIVATE,
        m_fd,
        fileOffset
    );
    
    if (result.data == MAP_FAILED) {
        std::cerr << "[StreamingGGUF] mmap failed" << std::endl;
        result.data = nullptr;
        return result;
    }
#endif
    
    result.size = info.size;
    return result;
}

bool StreamingGGUFLoader::LoadTensorData(const TensorInfo& info, void* dst, size_t dstSize) {
    if (!m_isOpen || !dst || dstSize < info.size) return false;
    
    uint64_t fileOffset = m_tensorDataOffset + info.offset;
    return ReadAt(fileOffset, dst, info.size);
}

// ============================================================================
// Private Helpers
// ============================================================================

bool StreamingGGUFLoader::ReadAt(uint64_t offset, void* dst, size_t size) {
#ifdef _WIN32
    OVERLAPPED ov = {};
    ov.Offset = (DWORD)(offset & 0xFFFFFFFF);
    ov.OffsetHigh = (DWORD)(offset >> 32);
    
    DWORD read = 0;
    return ReadFile(m_hFile, dst, (DWORD)size, &read, &ov) && read == size;
#else
    return pread(m_fd, dst, size, offset) == (ssize_t)size;
#endif
}

bool StreamingGGUFLoader::ParseTensorInfo(TensorInfo& info) {
    // Read name length
    uint64_t nameLen;
    if (!ReadAt(m_iteratorOffset, &nameLen, sizeof(nameLen))) return false;
    m_iteratorOffset += sizeof(nameLen);
    
    // Read name
    info.name.resize(nameLen);
    if (!ReadAt(m_iteratorOffset, &info.name[0], nameLen)) return false;
    m_iteratorOffset += nameLen;
    
    // Read type
    if (!ReadAt(m_iteratorOffset, &info.type, sizeof(info.type))) return false;
    m_iteratorOffset += sizeof(info.type);
    
    // Read dimensions
    uint32_t numDims;
    if (!ReadAt(m_iteratorOffset, &numDims, sizeof(numDims))) return false;
    m_iteratorOffset += sizeof(numDims);
    
    info.shape.resize(numDims);
    for (uint32_t i = 0; i < numDims; ++i) {
        if (!ReadAt(m_iteratorOffset, &info.shape[i], sizeof(info.shape[i]))) return false;
        m_iteratorOffset += sizeof(info.shape[i]);
    }
    
    // Read offset
    if (!ReadAt(m_iteratorOffset, &info.offset, sizeof(info.offset))) return false;
    m_iteratorOffset += sizeof(info.offset);
    
    // Calculate size
    info.size = info.ByteSize();
    
    return true;
}

bool StreamingGGUFLoader::SkipMetadata() {
    // Skip over metadata section (we don't parse it in streaming mode)
    // This is a simplified skip - just read and discard
    for (uint64_t i = 0; i < m_metadataCount; ++i) {
        // Read key length
        uint64_t keyLen;
        if (!ReadAt(m_iteratorOffset, &keyLen, sizeof(keyLen))) return false;
        m_iteratorOffset += sizeof(keyLen) + keyLen;
        
        // Read type
        uint32_t type;
        if (!ReadAt(m_iteratorOffset - sizeof(keyLen) - keyLen + sizeof(keyLen) + keyLen, 
                    &type, sizeof(type))) return false;
        m_iteratorOffset += sizeof(type);
        
        // Skip value based on type
        switch (type) {
            case 0: case 1: m_iteratorOffset += 1; break;  // uint8/int8
            case 2: case 3: m_iteratorOffset += 2; break;  // uint16/int16
            case 4: case 5: case 6: m_iteratorOffset += 4; break;  // uint32/int32/float32
            case 7: m_iteratorOffset += 1; break;  // bool
            case 8: {  // string
                uint64_t strLen;
                if (!ReadAt(m_iteratorOffset, &strLen, sizeof(strLen))) return false;
                m_iteratorOffset += sizeof(strLen) + strLen;
                break;
            }
            case 10: case 11: m_iteratorOffset += 8; break;  // uint64/int64
            case 12: m_iteratorOffset += 8; break;  // float64
            default: return false;
        }
    }
    return true;
}

// ============================================================================
// Metadata Access (simplified - returns defaults)
// ============================================================================
int64_t StreamingGGUFLoader::GetMetadataInt(const std::string& key, int64_t defaultValue) const {
    // TODO: Implement metadata parsing and lookup
    // For now, return defaults based on key patterns
    if (key.find("embedding_length") != std::string::npos) return 4096;
    if (key.find("head_count") != std::string::npos) return 32;
    if (key.find("feed_forward_length") != std::string::npos) return 11008;
    if (key.find("vocab_size") != std::string::npos) return 32000;
    if (key.find("context_length") != std::string::npos) return 2048;
    return defaultValue;
}

std::string StreamingGGUFLoader::GetMetadataString(const std::string& key, const std::string& defaultValue) const {
    // TODO: Implement metadata parsing and lookup
    return defaultValue;
}

// ============================================================================
// TensorView Creation
// ============================================================================
TensorView StreamingGGUFLoader::CreateTensorView(const TensorInfo& info) {
    if (!m_isOpen) return TensorView();
    
    // Create mmap-backed TensorView
    TensorView::MmapInfo mmapInfo;
    mmapInfo.base = nullptr;  // Will be set by MapTensor
    mmapInfo.fileOffset = m_tensorDataOffset;
    mmapInfo.tensorOffset = info.offset;
    mmapInfo.dataSize = info.size;
    mmapInfo.type = static_cast<GGMLType>(info.type);
    mmapInfo.shape = info.shape;
    
    // Memory map the tensor
    MmappedTensor mmapTensor = MapTensor(info);
    if (!mmapTensor.IsValid()) {
        return TensorView();
    }
    
    // Update base pointer
    mmapInfo.base = mmapTensor.data;
    
    // Note: The MmappedTensor is not stored here - the caller manages it
    // In a real implementation, you'd want to manage mapping lifetime
    
    return TensorView(mmapInfo);
}

} // namespace Runtime
} // namespace RawrXD
