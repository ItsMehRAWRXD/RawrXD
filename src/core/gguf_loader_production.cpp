// =============================================================================
// RawrXD-CoreRuntime: Production GGUF Loader Implementation
// =============================================================================
// Zero-dependency model loading with memory-mapped streaming
// =============================================================================

#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/gguf_loader_production.h"
#include <algorithm>
#include <cstring>
#include <cstdio>

// Platform-specific
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Core {

// =============================================================================
// Memory-Mapped File Implementation
// =============================================================================

MemoryMappedFile::MemoryMappedFile() 
    : m_data(nullptr), m_size(0)
#ifdef _WIN32
    , m_fileHandle(INVALID_HANDLE_VALUE), m_mapHandle(nullptr)
#else
    , m_fd(-1)
#endif
{
}

MemoryMappedFile::~MemoryMappedFile() {
    Close();
}

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept
    : m_data(other.m_data), m_size(other.m_size)
#ifdef _WIN32
    , m_fileHandle(other.m_fileHandle), m_mapHandle(other.m_mapHandle)
#else
    , m_fd(other.m_fd)
#endif
{
    other.m_data = nullptr;
    other.m_size = 0;
#ifdef _WIN32
    other.m_fileHandle = INVALID_HANDLE_VALUE;
    other.m_mapHandle = nullptr;
#else
    other.m_fd = -1;
#endif
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept {
    if (this != &other) {
        Close();
        m_data = other.m_data;
        m_size = other.m_size;
#ifdef _WIN32
        m_fileHandle = other.m_fileHandle;
        m_mapHandle = other.m_mapHandle;
        other.m_fileHandle = INVALID_HANDLE_VALUE;
        other.m_mapHandle = nullptr;
#else
        m_fd = other.m_fd;
        other.m_fd = -1;
#endif
        other.m_data = nullptr;
        other.m_size = 0;
    }
    return *this;
}

bool MemoryMappedFile::Open(const char* path) {
    if (!path || m_data) return false;
    
#ifdef _WIN32
    m_fileHandle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_fileHandle == INVALID_HANDLE_VALUE) return false;
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(m_fileHandle, &fileSize)) {
        CloseHandle(m_fileHandle);
        m_fileHandle = INVALID_HANDLE_VALUE;
        return false;
    }
    m_size = static_cast<size_t>(fileSize.QuadPart);
    
    m_mapHandle = CreateFileMapping(m_fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m_mapHandle) {
        CloseHandle(m_fileHandle);
        m_fileHandle = INVALID_HANDLE_VALUE;
        return false;
    }
    
    m_data = static_cast<uint8_t*>(MapViewOfFile(m_mapHandle, FILE_MAP_READ, 0, 0, 0));
    if (!m_data) {
        CloseHandle(m_mapHandle);
        CloseHandle(m_fileHandle);
        m_mapHandle = nullptr;
        m_fileHandle = INVALID_HANDLE_VALUE;
        return false;
    }
#else
    m_fd = ::open(path, O_RDONLY);
    if (m_fd < 0) return false;
    
    off_t fileSize = lseek(m_fd, 0, SEEK_END);
    if (fileSize < 0) {
        ::close(m_fd);
        m_fd = -1;
        return false;
    }
    m_size = static_cast<size_t>(fileSize);
    
    m_data = static_cast<uint8_t*>(mmap(nullptr, m_size, PROT_READ, MAP_PRIVATE, m_fd, 0));
    if (m_data == MAP_FAILED) {
        ::close(m_fd);
        m_fd = -1;
        m_data = nullptr;
        return false;
    }
#endif
    
    return true;
}

void MemoryMappedFile::Close() {
    if (!m_data) return;
    
#ifdef _WIN32
    UnmapViewOfFile(m_data);
    if (m_mapHandle) CloseHandle(m_mapHandle);
    if (m_fileHandle != INVALID_HANDLE_VALUE) CloseHandle(m_fileHandle);
    m_mapHandle = nullptr;
    m_fileHandle = INVALID_HANDLE_VALUE;
#else
    munmap(m_data, m_size);
    if (m_fd >= 0) ::close(m_fd);
    m_fd = -1;
#endif
    
    m_data = nullptr;
    m_size = 0;
}

// =============================================================================
// Tensor Descriptor
// =============================================================================

uint64_t TensorDescriptor::ElementCount() const {
    uint64_t count = 1;
    for (auto dim : dimensions) count *= dim;
    return count;
}

size_t TensorDescriptor::ElementSize() const {
    switch (type) {
        case GGMLType::F32:  return 4;
        case GGMLType::F16:  return 2;
        case GGMLType::Q4_0: return 2;  // 4-bit quantized
        case GGMLType::Q4_1: return 2;
        case GGMLType::Q5_0: return 2;
        case GGMLType::Q5_1: return 2;
        case GGMLType::Q8_0: return 2;
        case GGMLType::Q8_1: return 2;
        case GGMLType::Q4_K: return 2;
        case GGMLType::Q5_K: return 2;
        case GGMLType::Q6_K: return 2;
        case GGMLType::Q8_K: return 1;
        case GGMLType::I8:   return 1;
        case GGMLType::I16:  return 2;
        case GGMLType::I32:  return 4;
        case GGMLType::I64:  return 8;
        case GGMLType::F64:  return 8;
        case GGMLType::BF16: return 2;
        default:             return 4;
    }
}

// =============================================================================
// Metadata Entry
// =============================================================================

uint32_t MetadataEntry::AsUInt32(uint32_t defaultVal) const {
    switch (type) {
        case MetadataValueType::UINT8:  return value.u8;
        case MetadataValueType::INT8:   return static_cast<uint32_t>(value.i8);
        case MetadataValueType::UINT16: return value.u16;
        case MetadataValueType::INT16:  return static_cast<uint32_t>(value.i16);
        case MetadataValueType::UINT32: return value.u32;
        case MetadataValueType::INT32:  return static_cast<uint32_t>(value.i32);
        case MetadataValueType::UINT64: return static_cast<uint32_t>(value.u64);
        case MetadataValueType::INT64:  return static_cast<uint32_t>(value.i64);
        case MetadataValueType::FLOAT32: return static_cast<uint32_t>(value.f32);
        case MetadataValueType::BOOL:   return value.b ? 1 : 0;
        default: return defaultVal;
    }
}

int32_t MetadataEntry::AsInt32(int32_t defaultVal) const {
    switch (type) {
        case MetadataValueType::INT8:   return value.i8;
        case MetadataValueType::INT16:  return value.i16;
        case MetadataValueType::INT32:  return value.i32;
        case MetadataValueType::INT64:  return static_cast<int32_t>(value.i64);
        case MetadataValueType::UINT8:  return static_cast<int32_t>(value.u8);
        case MetadataValueType::UINT16: return static_cast<int32_t>(value.u16);
        case MetadataValueType::UINT32: return static_cast<int32_t>(value.u32);
        case MetadataValueType::UINT64: return static_cast<int32_t>(value.u64);
        case MetadataValueType::FLOAT32: return static_cast<int32_t>(value.f32);
        case MetadataValueType::BOOL:   return value.b ? 1 : 0;
        default: return defaultVal;
    }
}

float MetadataEntry::AsFloat(float defaultVal) const {
    switch (type) {
        case MetadataValueType::FLOAT32: return value.f32;
        case MetadataValueType::FLOAT64: return static_cast<float>(value.f64);
        case MetadataValueType::INT32:   return static_cast<float>(value.i32);
        case MetadataValueType::INT64:   return static_cast<float>(value.i64);
        case MetadataValueType::UINT32:  return static_cast<float>(value.u32);
        case MetadataValueType::UINT64:  return static_cast<float>(value.u64);
        default: return defaultVal;
    }
}

const char* MetadataEntry::AsString(const char* defaultVal) const {
    if (type == MetadataValueType::STRING) return strValue.c_str();
    return defaultVal;
}

uint64_t MetadataEntry::AsUInt64(uint64_t defaultVal) const {
    switch (type) {
        case MetadataValueType::UINT64: return value.u64;
        case MetadataValueType::UINT32: return value.u32;
        case MetadataValueType::UINT16: return value.u16;
        case MetadataValueType::UINT8:  return value.u8;
        case MetadataValueType::INT64:   return static_cast<uint64_t>(value.i64);
        case MetadataValueType::INT32:  return static_cast<uint64_t>(value.i32);
        case MetadataValueType::INT16:  return static_cast<uint64_t>(value.i16);
        case MetadataValueType::INT8:   return static_cast<uint64_t>(value.i8);
        default: return defaultVal;
    }
}

// =============================================================================
// GGUF Loader Implementation
// =============================================================================

class GGUFLoaderProduction::Impl {
public:
    MemoryMappedFile mappedFile;
    std::string path;
    uint32_t version = 0;
    bool loaded = false;
    
    ModelArchitecture arch;
    std::vector<MetadataEntry> metadata;
    std::vector<TensorDescriptor> tensors;
    
    // Fast lookup
    std::unordered_map<std::string, size_t> metadataMap;
    std::unordered_map<std::string, size_t> tensorMap;
    
    ProgressCallback progressCallback;
    
    // Parsing state
    const uint8_t* data = nullptr;
    size_t dataSize = 0;
    size_t currentOffset = 0;
    
    bool ParseHeader();
    bool ParseMetadata();
    bool ParseTensors();
    bool ParseMetadataValue(MetadataEntry& entry);
    bool ParseString(std::string& str);
    bool ParseTensorInfo(TensorDescriptor& tensor);
    void ExtractArchitecture();
};

GGUFLoaderProduction::GGUFLoaderProduction() : pImpl(std::make_unique<Impl>()) {}
GGUFLoaderProduction::~GGUFLoaderProduction() = default;
GGUFLoaderProduction::GGUFLoaderProduction(GGUFLoaderProduction&&) noexcept = default;
GGUFLoaderProduction& GGUFLoaderProduction::operator=(GGUFLoaderProduction&&) noexcept = default;

bool GGUFLoaderProduction::Load(const char* path, bool memoryMap) {
    if (!path || pImpl->loaded) return false;
    
    if (memoryMap) {
        if (!pImpl->mappedFile.Open(path)) return false;
        pImpl->data = pImpl->mappedFile.Data();
        pImpl->dataSize = pImpl->mappedFile.Size();
    } else {
        // File read mode (not implemented for brevity)
        return false;
    }
    
    pImpl->path = path;
    pImpl->currentOffset = 0;
    
    if (pImpl->progressCallback) {
        pImpl->progressCallback(0, 100, "Parsing header");
    }
    
    if (!pImpl->ParseHeader()) {
        Unload();
        return false;
    }
    
    if (pImpl->progressCallback) {
        pImpl->progressCallback(33, 100, "Parsing metadata");
    }
    
    if (!pImpl->ParseMetadata()) {
        Unload();
        return false;
    }
    
    if (pImpl->progressCallback) {
        pImpl->progressCallback(66, 100, "Parsing tensors");
    }
    
    if (!pImpl->ParseTensors()) {
        Unload();
        return false;
    }
    
    pImpl->ExtractArchitecture();
    pImpl->loaded = true;
    
    if (pImpl->progressCallback) {
        pImpl->progressCallback(100, 100, "Complete");
    }
    
    return true;
}

void GGUFLoaderProduction::Unload() {
    pImpl->mappedFile.Close();
    pImpl->metadata.clear();
    pImpl->tensors.clear();
    pImpl->metadataMap.clear();
    pImpl->tensorMap.clear();
    pImpl->data = nullptr;
    pImpl->dataSize = 0;
    pImpl->currentOffset = 0;
    pImpl->loaded = false;
    pImpl->version = 0;
    pImpl->path.clear();
}

bool GGUFLoaderProduction::IsLoaded() const {
    return pImpl->loaded;
}

const char* GGUFLoaderProduction::GetPath() const {
    return pImpl->path.c_str();
}

uint32_t GGUFLoaderProduction::GetVersion() const {
    return pImpl->version;
}

const ModelArchitecture& GGUFLoaderProduction::GetArchitecture() const {
    return pImpl->arch;
}

bool GGUFLoaderProduction::HasMetadata(const char* key) const {
    return pImpl->metadataMap.find(key) != pImpl->metadataMap.end();
}

const MetadataEntry* GGUFLoaderProduction::GetMetadata(const char* key) const {
    auto it = pImpl->metadataMap.find(key);
    if (it != pImpl->metadataMap.end()) {
        return &pImpl->metadata[it->second];
    }
    return nullptr;
}

uint32_t GGUFLoaderProduction::GetMetadataCount() const {
    return static_cast<uint32_t>(pImpl->metadata.size());
}

const MetadataEntry* GGUFLoaderProduction::GetMetadataByIndex(uint32_t index) const {
    if (index < pImpl->metadata.size()) {
        return &pImpl->metadata[index];
    }
    return nullptr;
}

uint32_t GGUFLoaderProduction::GetTensorCount() const {
    return static_cast<uint32_t>(pImpl->tensors.size());
}

const TensorDescriptor* GGUFLoaderProduction::GetTensor(const char* name) const {
    auto it = pImpl->tensorMap.find(name);
    if (it != pImpl->tensorMap.end()) {
        return &pImpl->tensors[it->second];
    }
    return nullptr;
}

const TensorDescriptor* GGUFLoaderProduction::GetTensorByIndex(uint32_t index) const {
    if (index < pImpl->tensors.size()) {
        return &pImpl->tensors[index];
    }
    return nullptr;
}

const void* GGUFLoaderProduction::ReadTensorData(const TensorDescriptor& tensor) {
    if (!pImpl->data || tensor.dataOffset + tensor.size > pImpl->dataSize) {
        return nullptr;
    }
    return pImpl->data + tensor.dataOffset;
}

void GGUFLoaderProduction::SetProgressCallback(ProgressCallback callback) {
    pImpl->progressCallback = callback;
}

size_t GGUFLoaderProduction::GetTotalFileSize() const {
    return pImpl->dataSize;
}

size_t GGUFLoaderProduction::GetMappedMemorySize() const {
    return pImpl->mappedFile.Size();
}

// =============================================================================
// Parsing Implementation
// =============================================================================

bool GGUFLoaderProduction::Impl::ParseHeader() {
    if (dataSize < 24) return false;
    
    // Read magic
    uint32_t magic = *reinterpret_cast<const uint32_t*>(data + currentOffset);
    currentOffset += 4;
    
    if (magic != GGUF_MAGIC) return false;
    
    // Read version
    version = *reinterpret_cast<const uint32_t*>(data + currentOffset);
    currentOffset += 4;
    
    if (version > GGUF_VERSION) return false;
    
    // Read tensor count
    uint64_t tensorCount = *reinterpret_cast<const uint64_t*>(data + currentOffset);
    currentOffset += 8;
    
    // Read metadata count
    uint64_t metadataCount = *reinterpret_cast<const uint64_t*>(data + currentOffset);
    currentOffset += 8;
    
    tensors.reserve(tensorCount);
    metadata.reserve(metadataCount);
    
    return true;
}

bool GGUFLoaderProduction::Impl::ParseMetadata() {
    uint64_t metadataCount = metadata.capacity();
    
    for (uint64_t i = 0; i < metadataCount; ++i) {
        MetadataEntry entry;
        
        // Read key
        if (!ParseString(entry.key)) return false;
        
        // Read value
        if (!ParseMetadataValue(entry)) return false;
        
        metadataMap[entry.key] = metadata.size();
        metadata.push_back(std::move(entry));
    }
    
    return true;
}

bool GGUFLoaderProduction::Impl::ParseMetadataValue(MetadataEntry& entry) {
    if (currentOffset + 4 > dataSize) return false;
    
    uint32_t type = *reinterpret_cast<const uint32_t*>(data + currentOffset);
    currentOffset += 4;
    entry.type = static_cast<MetadataValueType>(type);
    
    switch (entry.type) {
        case MetadataValueType::UINT8:
            if (currentOffset + 1 > dataSize) return false;
            entry.value.u8 = *reinterpret_cast<const uint8_t*>(data + currentOffset);
            currentOffset += 1;
            break;
            
        case MetadataValueType::INT8:
            if (currentOffset + 1 > dataSize) return false;
            entry.value.i8 = *reinterpret_cast<const int8_t*>(data + currentOffset);
            currentOffset += 1;
            break;
            
        case MetadataValueType::UINT16:
            if (currentOffset + 2 > dataSize) return false;
            entry.value.u16 = *reinterpret_cast<const uint16_t*>(data + currentOffset);
            currentOffset += 2;
            break;
            
        case MetadataValueType::INT16:
            if (currentOffset + 2 > dataSize) return false;
            entry.value.i16 = *reinterpret_cast<const int16_t*>(data + currentOffset);
            currentOffset += 2;
            break;
            
        case MetadataValueType::UINT32:
            if (currentOffset + 4 > dataSize) return false;
            entry.value.u32 = *reinterpret_cast<const uint32_t*>(data + currentOffset);
            currentOffset += 4;
            break;
            
        case MetadataValueType::INT32:
            if (currentOffset + 4 > dataSize) return false;
            entry.value.i32 = *reinterpret_cast<const int32_t*>(data + currentOffset);
            currentOffset += 4;
            break;
            
        case MetadataValueType::FLOAT32:
            if (currentOffset + 4 > dataSize) return false;
            entry.value.f32 = *reinterpret_cast<const float*>(data + currentOffset);
            currentOffset += 4;
            break;
            
        case MetadataValueType::UINT64:
            if (currentOffset + 8 > dataSize) return false;
            entry.value.u64 = *reinterpret_cast<const uint64_t*>(data + currentOffset);
            currentOffset += 8;
            break;
            
        case MetadataValueType::INT64:
            if (currentOffset + 8 > dataSize) return false;
            entry.value.i64 = *reinterpret_cast<const int64_t*>(data + currentOffset);
            currentOffset += 8;
            break;
            
        case MetadataValueType::FLOAT64:
            if (currentOffset + 8 > dataSize) return false;
            entry.value.f64 = *reinterpret_cast<const double*>(data + currentOffset);
            currentOffset += 8;
            break;
            
        case MetadataValueType::BOOL:
            if (currentOffset + 1 > dataSize) return false;
            entry.value.b = *reinterpret_cast<const uint8_t*>(data + currentOffset) != 0;
            currentOffset += 1;
            break;
            
        case MetadataValueType::STRING:
            if (!ParseString(entry.strValue)) return false;
            break;
            
        case MetadataValueType::ARRAY:
            // Array parsing (simplified)
            {
                uint32_t elemType = *reinterpret_cast<const uint32_t*>(data + currentOffset);
                currentOffset += 4;
                uint64_t count = *reinterpret_cast<const uint64_t*>(data + currentOffset);
                currentOffset += 8;
                
                // Skip array data for now
                for (uint64_t j = 0; j < count; ++j) {
                    MetadataEntry elem;
                    elem.type = static_cast<MetadataValueType>(elemType);
                    if (!ParseMetadataValue(elem)) return false;
                    entry.arrayValues.push_back(std::move(elem));
                }
            }
            break;
            
        default:
            return false;
    }
    
    return true;
}

bool GGUFLoaderProduction::Impl::ParseString(std::string& str) {
    if (currentOffset + 8 > dataSize) return false;
    
    uint64_t len = *reinterpret_cast<const uint64_t*>(data + currentOffset);
    currentOffset += 8;
    
    if (currentOffset + len > dataSize) return false;
    
    str.assign(reinterpret_cast<const char*>(data + currentOffset), len);
    currentOffset += len;
    
    return true;
}

bool GGUFLoaderProduction::Impl::ParseTensors() {
    // Tensor info comes after metadata
    // Each tensor: name (string), type (uint32), offset (uint64)
    
    for (size_t i = 0; i < tensors.capacity(); ++i) {
        TensorDescriptor tensor;
        
        if (!ParseTensorInfo(tensor)) return false;
        
        tensorMap[tensor.name] = tensors.size();
        tensors.push_back(std::move(tensor));
    }
    
    // Calculate tensor data offsets
    // Data starts at currentOffset (aligned)
    size_t dataBase = currentOffset;
    
    for (auto& tensor : tensors) {
        tensor.dataOffset = dataBase + tensor.offset;
    }
    
    return true;
}

bool GGUFLoaderProduction::Impl::ParseTensorInfo(TensorDescriptor& tensor) {
    // Read name
    if (!ParseString(tensor.name)) return false;
    
    // Read dimensions
    if (currentOffset + 4 > dataSize) return false;
    uint32_t nDims = *reinterpret_cast<const uint32_t*>(data + currentOffset);
    currentOffset += 4;
    
    if (nDims > 4) return false; // Sanity check
    
    tensor.dimensions.resize(nDims);
    for (uint32_t i = 0; i < nDims; ++i) {
        if (currentOffset + 8 > dataSize) return false;
        tensor.dimensions[i] = *reinterpret_cast<const uint64_t*>(data + currentOffset);
        currentOffset += 8;
    }
    
    // Read type
    if (currentOffset + 4 > dataSize) return false;
    uint32_t type = *reinterpret_cast<const uint32_t*>(data + currentOffset);
    currentOffset += 4;
    tensor.type = static_cast<GGMLType>(type);
    
    // Read offset
    if (currentOffset + 8 > dataSize) return false;
    tensor.offset = *reinterpret_cast<const uint64_t*>(data + currentOffset);
    currentOffset += 8;
    
    // Calculate size
    tensor.size = tensor.ElementCount() * tensor.ElementSize();
    
    return true;
}

void GGUFLoaderProduction::Impl::ExtractArchitecture() {
    // Extract common architecture fields from metadata
    auto getMeta = [this](const char* key) -> const MetadataEntry* {
        auto it = metadataMap.find(key);
        if (it != metadataMap.end()) return &metadata[it->second];
        return nullptr;
    };
    
    if (auto e = getMeta("general.architecture")) {
        arch.name = e->AsString();
    }
    if (auto e = getMeta("general.name")) {
        // Model name
    }
    if (auto e = getMeta("llama.vocab_size")) {
        arch.vocabSize = e->AsUInt32();
    }
    if (auto e = getMeta("llama.hidden_size")) {
        arch.hiddenSize = e->AsUInt32();
    }
    if (auto e = getMeta("llama.block_count")) {
        arch.numLayers = e->AsUInt32();
    }
    if (auto e = getMeta("llama.attention.head_count")) {
        arch.numHeads = e->AsUInt32();
    }
    if (auto e = getMeta("llama.attention.head_count_kv")) {
        arch.numKVHeads = e->AsUInt32();
    }
    if (auto e = getMeta("llama.context_length")) {
        arch.contextLength = e->AsUInt32();
    }
    if (auto e = getMeta("llama.feed_forward_length")) {
        arch.intermediateSize = e->AsUInt32();
    }
    if (auto e = getMeta("llama.rope.freq_base")) {
        arch.ropeTheta = e->AsFloat();
    }
    if (auto e = getMeta("llama.rope.scale_linear")) {
        arch.ropeScaling = e->AsFloat();
    }
    if (auto e = getMeta("tokenizer.ggml.bos_token_id")) {
        arch.bosToken = e->AsUInt32();
    }
    if (auto e = getMeta("tokenizer.ggml.eos_token_id")) {
        arch.eosToken = e->AsUInt32();
    }
    if (auto e = getMeta("tokenizer.ggml.padding_token_id")) {
        arch.padToken = e->AsUInt32();
    }
    
    // Detect quantization from first tensor
    if (!tensors.empty()) {
        arch.weightType = tensors[0].type;
        arch.hasQuantization = arch.weightType != GGMLType::F32 && 
                               arch.weightType != GGMLType::F16;
    }
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

GGUFLoaderHandle* GGUFLoader_Create() {
    return reinterpret_cast<GGUFLoaderHandle*>(new GGUFLoaderProduction());
}

void GGUFLoader_Destroy(GGUFLoaderHandle* handle) {
    delete reinterpret_cast<GGUFLoaderProduction*>(handle);
}

int GGUFLoader_Load(GGUFLoaderHandle* handle, const char* path) {
    auto* loader = reinterpret_cast<GGUFLoaderProduction*>(handle);
    if (!loader) return 0;
    return loader->Load(path, true) ? 1 : 0;
}

void GGUFLoader_Unload(GGUFLoaderHandle* handle) {
    auto* loader = reinterpret_cast<GGUFLoaderProduction*>(handle);
    if (loader) loader->Unload();
}

int GGUFLoader_IsLoaded(GGUFLoaderHandle* handle) {
    auto* loader = reinterpret_cast<GGUFLoaderProduction*>(handle);
    if (!loader) return 0;
    return loader->IsLoaded() ? 1 : 0;
}

uint32_t GGUFLoader_GetTensorCount(GGUFLoaderHandle* handle) {
    auto* loader = reinterpret_cast<GGUFLoaderProduction*>(handle);
    if (!loader) return 0;
    return loader->GetTensorCount();
}

int GGUFLoader_GetTensorInfo(GGUFLoaderHandle* handle, uint32_t index,
                              char* nameOut, size_t nameSize,
                              uint32_t* dimsOut, uint32_t maxDims,
                              uint64_t* sizeOut) {
    auto* loader = reinterpret_cast<GGUFLoaderProduction*>(handle);
    if (!loader) return 0;
    
    const auto* tensor = loader->GetTensorByIndex(index);
    if (!tensor) return 0;
    
    if (nameOut && nameSize > 0) {
        strncpy(nameOut, tensor->name.c_str(), nameSize - 1);
        nameOut[nameSize - 1] = '\0';
    }
    
    if (dimsOut && maxDims > 0) {
        uint32_t n = static_cast<uint32_t>(std::min(tensor->dimensions.size(), 
                                                     static_cast<size_t>(maxDims)));
        for (uint32_t i = 0; i < n; ++i) {
            dimsOut[i] = static_cast<uint32_t>(tensor->dimensions[i]);
        }
    }
    
    if (sizeOut) {
        *sizeOut = tensor->size;
    }
    
    return 1;
}

const void* GGUFLoader_ReadTensorData(GGUFLoaderHandle* handle, const char* name) {
    auto* loader = reinterpret_cast<GGUFLoaderProduction*>(handle);
    if (!loader) return nullptr;
    
    const auto* tensor = loader->GetTensor(name);
    if (!tensor) return nullptr;
    
    return loader->ReadTensorData(*tensor);
}

} // extern "C"

} // namespace Core
} // namespace RawrXD
