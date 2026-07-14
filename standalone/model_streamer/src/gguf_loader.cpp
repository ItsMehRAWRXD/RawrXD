#include "gguf_loader.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Model {

// ============================================================================
// GGUFLoader Implementation
// ============================================================================

class GGUFLoaderImpl {
public:
    GGUFLoaderImpl() = default;
    ~GGUFLoaderImpl() { Close(); }

    bool Open(const std::string& filepath);
    void Close();
    bool IsOpen() const { return m_file.is_open(); }
    
    GGUFHeader GetHeader() const { return m_header; }
    const ModelMetadata& GetMetadata();
    ModelArchitecture GetArchitecture() const;
    std::vector<TensorInfo> GetTensorInfo() const;
    bool FindTensor(const std::string& name, TensorInfo& outInfo) const;
    bool LoadTensor(const std::string& name, std::vector<uint8_t>& data);
    bool LoadTensorMapped(const std::string& name, const uint8_t*& data, size_t& size);
    void UnloadTensorMapped(const std::string& name);
    uint64_t GetFileSize() const;
    uint64_t GetMemoryUsage() const;
    std::string GetLastError() const { return m_lastError; }

private:
    bool ParseHeader();
    bool ParseMetadata();
    bool BuildTensorIndex();
    bool ReadValue(MetadataType type, std::vector<uint8_t>& value);
    bool ReadString(std::string& value);
    bool ReadArray(MetadataType elemType, std::vector<uint8_t>& value);
    
    template<typename T>
    bool ReadRaw(T& value) {
        m_file.read(reinterpret_cast<char*>(&value), sizeof(T));
        return m_file.good();
    }

    std::ifstream m_file;
    std::string m_filepath;
    GGUFHeader m_header{};
    ModelMetadata m_metadata;
    std::vector<TensorInfo> m_tensors;
    std::map<std::string, size_t> m_tensorMap; // name -> index
    uint64_t m_tensorDataOffset = 0;
    uint64_t m_memoryUsage = 0;
    std::string m_lastError;
    bool m_metadataParsed = false;
    
#ifdef _WIN32
    struct MappedRegion {
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMapping = nullptr;
        const uint8_t* data = nullptr;
        size_t size = 0;
    };
    std::map<std::string, MappedRegion> m_mappedRegions;
#else
    struct MappedRegion {
        int fd = -1;
        const uint8_t* data = nullptr;
        size_t size = 0;
    };
    std::map<std::string, MappedRegion> m_mappedRegions;
#endif
};

bool GGUFLoaderImpl::Open(const std::string& filepath) {
    Close();
    
    m_filepath = filepath;
    m_file.open(filepath, std::ios::binary);
    
    if (!m_file.is_open()) {
        m_lastError = "Failed to open file: " + filepath;
        return false;
    }
    
    if (!ParseHeader()) {
        return false;
    }
    
    if (!ParseMetadata()) {
        return false;
    }
    
    if (!BuildTensorIndex()) {
        return false;
    }
    
    return true;
}

void GGUFLoaderImpl::Close() {
    // Unmap all mapped regions
    for (auto& [name, region] : m_mappedRegions) {
#ifdef _WIN32
        if (region.data) UnmapViewOfFile(region.data);
        if (region.hMapping) CloseHandle(region.hMapping);
        if (region.hFile != INVALID_HANDLE_VALUE) CloseHandle(region.hFile);
#else
        if (region.data) munmap(const_cast<uint8_t*>(region.data), region.size);
        if (region.fd >= 0) close(region.fd);
#endif
    }
    m_mappedRegions.clear();
    
    if (m_file.is_open()) {
        m_file.close();
    }
    
    m_tensors.clear();
    m_tensorMap.clear();
    m_memoryUsage = 0;
    m_metadataParsed = false;
}

bool GGUFLoaderImpl::ParseHeader() {
    m_file.seekg(0);
    
    if (!ReadRaw(m_header.magic)) {
        m_lastError = "Failed to read magic";
        return false;
    }
    
    if (m_header.magic != GGUF_MAGIC) {
        m_lastError = "Invalid GGUF magic (expected 0x46554747)";
        return false;
    }
    
    if (!ReadRaw(m_header.version)) {
        m_lastError = "Failed to read version";
        return false;
    }
    
    if (m_header.version != 2 && m_header.version != 3) {
        m_lastError = "Unsupported GGUF version: " + std::to_string(m_header.version);
        return false;
    }
    
    if (!ReadRaw(m_header.tensorCount)) {
        m_lastError = "Failed to read tensor count";
        return false;
    }
    
    if (!ReadRaw(m_header.metadataCount)) {
        m_lastError = "Failed to read metadata count";
        return false;
    }
    
    return true;
}

bool GGUFLoaderImpl::ParseMetadata() {
    if (m_metadataParsed) return true;
    
    for (uint64_t i = 0; i < m_header.metadataCount; ++i) {
        MetadataEntry entry;
        
        // Read key
        if (!ReadString(entry.key)) {
            m_lastError = "Failed to read metadata key " + std::to_string(i);
            return false;
        }
        
        // Read type
        uint32_t typeVal;
        if (!ReadRaw(typeVal)) {
            m_lastError = "Failed to read metadata type for key: " + entry.key;
            return false;
        }
        entry.type = static_cast<MetadataType>(typeVal);
        
        // Read value
        if (entry.type == MetadataType::Array) {
            // Array has element type + count
            uint32_t elemTypeVal;
            uint64_t count;
            if (!ReadRaw(elemTypeVal) || !ReadRaw(count)) {
                m_lastError = "Failed to read array header for: " + entry.key;
                return false;
            }
            MetadataType elemType = static_cast<MetadataType>(elemTypeVal);
            
            // Store as: elemType (4 bytes) + count (8 bytes) + raw data
            entry.rawValue.resize(12);
            std::memcpy(entry.rawValue.data(), &elemTypeVal, 4);
            std::memcpy(entry.rawValue.data() + 4, &count, 8);
            
            // Read elements
            for (uint64_t j = 0; j < count; ++j) {
                std::vector<uint8_t> elemValue;
                if (!ReadValue(elemType, elemValue)) {
                    m_lastError = "Failed to read array element " + std::to_string(j) + " for: " + entry.key;
                    return false;
                }
                entry.rawValue.insert(entry.rawValue.end(), elemValue.begin(), elemValue.end());
            }
        } else {
            if (!ReadValue(entry.type, entry.rawValue)) {
                m_lastError = "Failed to read metadata value for: " + entry.key;
                return false;
            }
        }
        
        m_metadata.entries[entry.key] = std::move(entry);
    }
    
    m_metadataParsed = true;
    return true;
}

bool GGUFLoaderImpl::ReadValue(MetadataType type, std::vector<uint8_t>& value) {
    switch (type) {
        case MetadataType::Uint8: {
            uint8_t v; if (!ReadRaw(v)) return false;
            value.resize(1); value[0] = v; return true;
        }
        case MetadataType::Int8: {
            int8_t v; if (!ReadRaw(v)) return false;
            value.resize(1); value[0] = static_cast<uint8_t>(v); return true;
        }
        case MetadataType::Uint16: {
            uint16_t v; if (!ReadRaw(v)) return false;
            value.resize(2); std::memcpy(value.data(), &v, 2); return true;
        }
        case MetadataType::Int16: {
            int16_t v; if (!ReadRaw(v)) return false;
            value.resize(2); std::memcpy(value.data(), &v, 2); return true;
        }
        case MetadataType::Uint32: {
            uint32_t v; if (!ReadRaw(v)) return false;
            value.resize(4); std::memcpy(value.data(), &v, 4); return true;
        }
        case MetadataType::Int32: {
            int32_t v; if (!ReadRaw(v)) return false;
            value.resize(4); std::memcpy(value.data(), &v, 4); return true;
        }
        case MetadataType::Float32: {
            float v; if (!ReadRaw(v)) return false;
            value.resize(4); std::memcpy(value.data(), &v, 4); return true;
        }
        case MetadataType::Uint64: {
            uint64_t v; if (!ReadRaw(v)) return false;
            value.resize(8); std::memcpy(value.data(), &v, 8); return true;
        }
        case MetadataType::Int64: {
            int64_t v; if (!ReadRaw(v)) return false;
            value.resize(8); std::memcpy(value.data(), &v, 8); return true;
        }
        case MetadataType::Float64: {
            double v; if (!ReadRaw(v)) return false;
            value.resize(8); std::memcpy(value.data(), &v, 8); return true;
        }
        case MetadataType::Bool: {
            uint8_t v; if (!ReadRaw(v)) return false;
            value.resize(1); value[0] = v; return true;
        }
        case MetadataType::String: {
            std::string s; if (!ReadString(s)) return false;
            value.resize(s.size());
            std::memcpy(value.data(), s.data(), s.size());
            return true;
        }
        default:
            return false;
    }
}

bool GGUFLoaderImpl::ReadString(std::string& value) {
    uint64_t len;
    if (!ReadRaw(len)) return false;
    
    if (len > 1024 * 1024) { // Sanity check: max 1MB string
        return false;
    }
    
    value.resize(len);
    if (len > 0) {
        m_file.read(value.data(), len);
        if (!m_file.good()) return false;
    }
    return true;
}

bool GGUFLoaderImpl::BuildTensorIndex() {
    m_tensors.clear();
    m_tensors.reserve(m_header.tensorCount);
    
    for (uint64_t i = 0; i < m_header.tensorCount; ++i) {
        TensorInfo info;
        
        // Read name
        if (!ReadString(info.name)) {
            m_lastError = "Failed to read tensor name " + std::to_string(i);
            return false;
        }
        
        // Read dimensions
        uint32_t nDims;
        if (!ReadRaw(nDims)) {
            m_lastError = "Failed to read tensor dimensions for: " + info.name;
            return false;
        }
        
        info.shape.resize(nDims);
        for (uint32_t d = 0; d < nDims; ++d) {
            uint64_t dim;
            if (!ReadRaw(dim)) {
                m_lastError = "Failed to read tensor dimension " + std::to_string(d) + " for: " + info.name;
                return false;
            }
            info.shape[d] = dim;
        }
        
        // Read type
        uint32_t typeVal;
        if (!ReadRaw(typeVal)) {
            m_lastError = "Failed to read tensor type for: " + info.name;
            return false;
        }
        info.type = static_cast<GGMLType>(typeVal);
        
        // Read offset
        if (!ReadRaw(info.offset)) {
            m_lastError = "Failed to read tensor offset for: " + info.name;
            return false;
        }
        
        // Calculate size
        info.size = GGUFLoader::CalculateTensorSize(info.shape, info.type);
        
        m_tensorMap[info.name] = m_tensors.size();
        m_tensors.push_back(std::move(info));
    }
    
    // Tensor data starts at current position (aligned)
    m_tensorDataOffset = m_file.tellg();
    
    return true;
}

ModelArchitecture GGUFLoaderImpl::GetArchitecture() const {
    ModelArchitecture arch;
    
    arch.name = m_metadata.GetString("general.architecture", "");
    arch.vocabSize = m_metadata.GetUint32("%s.vocab_size", 0);
    if (arch.vocabSize == 0) {
        arch.vocabSize = m_metadata.GetUint32("tokenizer.ggml.vocab_size", 0);
    }
    arch.contextLength = m_metadata.GetUint32("%s.context_length", 0);
    if (arch.contextLength == 0) {
        arch.contextLength = m_metadata.GetUint32("%s.block_count", 0) * 2; // Estimate
    }
    arch.embeddingDim = m_metadata.GetUint32("%s.embedding_length", 0);
    arch.numLayers = m_metadata.GetUint32("%s.block_count", 0);
    arch.numHeads = m_metadata.GetUint32("%s.attention.head_count", 0);
    arch.numKVHeads = m_metadata.GetUint32("%s.attention.head_count_kv", arch.numHeads);
    arch.hiddenDim = m_metadata.GetUint32("%s.feed_forward_length", 0);
    arch.normRMS = m_metadata.GetFloat32("%s.attention.layer_norm_rms_epsilon", 1e-6f);
    
    return arch;
}

std::vector<TensorInfo> GGUFLoaderImpl::GetTensorInfo() const {
    return m_tensors;
}

bool GGUFLoaderImpl::FindTensor(const std::string& name, TensorInfo& outInfo) const {
    auto it = m_tensorMap.find(name);
    if (it == m_tensorMap.end()) return false;
    outInfo = m_tensors[it->second];
    return true;
}

bool GGUFLoaderImpl::LoadTensor(const std::string& name, std::vector<uint8_t>& data) {
    TensorInfo info;
    if (!FindTensor(name, info)) {
        m_lastError = "Tensor not found: " + name;
        return false;
    }
    
    data.resize(info.size);
    
    m_file.seekg(m_tensorDataOffset + info.offset);
    m_file.read(reinterpret_cast<char*>(data.data()), info.size);
    
    if (!m_file.good()) {
        m_lastError = "Failed to read tensor data: " + name;
        return false;
    }
    
    m_memoryUsage += info.size;
    return true;
}

uint64_t GGUFLoaderImpl::GetFileSize() const {
    if (!m_file.is_open()) return 0;
    
    auto pos = m_file.tellg();
    m_file.seekg(0, std::ios::end);
    auto size = m_file.tellg();
    m_file.seekg(pos);
    return static_cast<uint64_t>(size);
}

uint64_t GGUFLoaderImpl::GetMemoryUsage() const {
    return m_memoryUsage;
}

// ============================================================================
// GGUFLoader Public Interface
// ============================================================================

GGUFLoader::GGUFLoader() : m_impl(std::make_unique<GGUFLoaderImpl>()) {}
GGUFLoader::~GGUFLoader() = default;

bool GGUFLoader::Open(const std::string& filepath) {
    return m_impl->Open(filepath);
}

void GGUFLoader::Close() {
    m_impl->Close();
}

bool GGUFLoader::IsOpen() const {
    return m_impl->IsOpen();
}

std::string GGUFLoader::GetFilePath() const {
    return m_impl->m_filepath;
}

GGUFHeader GGUFLoader::GetHeader() const {
    return m_impl->GetHeader();
}

const ModelMetadata& GGUFLoader::GetMetadata() {
    return m_impl->GetMetadata();
}

ModelArchitecture GGUFLoader::GetArchitecture() const {
    return m_impl->GetArchitecture();
}

std::vector<TensorInfo> GGUFLoader::GetTensorInfo() const {
    return m_impl->GetTensorInfo();
}

bool GGUFLoader::FindTensor(const std::string& name, TensorInfo& outInfo) const {
    return m_impl->FindTensor(name, outInfo);
}

bool GGUFLoader::LoadTensor(const std::string& name, std::vector<uint8_t>& data) {
    return m_impl->LoadTensor(name, data);
}

uint64_t GGUFLoader::GetFileSize() const {
    return m_impl->GetFileSize();
}

uint64_t GGUFLoader::GetMemoryUsage() const {
    return m_impl->GetMemoryUsage();
}

std::string GGUFLoader::GetLastError() const {
    return m_impl->GetLastError();
}

std::string GGUFLoader::GGMLTypeToString(GGMLType type) {
    switch (type) {
        case GGMLType::F32: return "F32";
        case GGMLType::F16: return "F16";
        case GGMLType::Q4_0: return "Q4_0";
        case GGMLType::Q4_1: return "Q4_1";
        case GGMLType::Q5_0: return "Q5_0";
        case GGMLType::Q5_1: return "Q5_1";
        case GGMLType::Q8_0: return "Q8_0";
        case GGMLType::Q8_1: return "Q8_1";
        case GGMLType::Q2_K: return "Q2_K";
        case GGMLType::Q3_K: return "Q3_K";
        case GGMLType::Q4_K: return "Q4_K";
        case GGMLType::Q5_K: return "Q5_K";
        case GGMLType::Q6_K: return "Q6_K";
        case GGMLType::Q8_K: return "Q8_K";
        default: return "UNKNOWN";
    }
}

size_t GGUFLoader::GGMLTypeSize(GGMLType type) {
    switch (type) {
        case GGMLType::F32: return 4;
        case GGMLType::F16: return 2;
        case GGMLType::Q4_0: return 18; // 32 elements in 18 bytes
        case GGMLType::Q4_1: return 20;
        case GGMLType::Q5_0: return 22;
        case GGMLType::Q5_1: return 24;
        case GGMLType::Q8_0: return 34;
        case GGMLType::Q8_1: return 36;
        case GGMLType::Q2_K: return 0; // Variable
        case GGMLType::Q3_K: return 0;
        case GGMLType::Q4_K: return 0;
        case GGMLType::Q5_K: return 0;
        case GGMLType::Q6_K: return 0;
        case GGMLType::Q8_K: return 0;
        default: return 0;
    }
}

size_t GGUFLoader::CalculateTensorSize(const std::vector<uint64_t>& shape, GGMLType type) {
    size_t numElements = 1;
    for (auto dim : shape) {
        numElements *= dim;
    }
    
    switch (type) {
        case GGMLType::F32:
            return numElements * 4;
        case GGMLType::F16:
            return numElements * 2;
        case GGMLType::Q4_0:
            return (numElements / 32) * 18 + (numElements % 32) * 4;
        case GGMLType::Q4_1:
            return (numElements / 32) * 20 + (numElements % 32) * 4;
        case GGMLType::Q8_0:
            return (numElements / 32) * 34 + (numElements % 32) * 4;
        default:
            // For k-quants, approximate
            return numElements / 2; // Rough estimate
    }
}

} // namespace Model
} // namespace RawrXD
