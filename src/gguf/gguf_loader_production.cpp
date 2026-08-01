//=============================================================================
// RawrXD GGUF Loader - PRODUCTION IMPLEMENTATION
// Zero dependencies, pure C++17, Windows/Linux compatible
//=============================================================================

#include "gguf_loader_production.hpp"
#include <algorithm>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include ?cntl.h>
#include <unistd.h>
#include "gguf_loader.h"
#endif

namespace RawrXD {

//=============================================================================
// Memory-Mapped File Implementation
//=============================================================================

MemoryMappedFile::MemoryMappedFile() 
    : data_(nullptr), size_(0)
#ifdef _WIN32
    , file_handle_(nullptr), map_handle_(nullptr)
#else
    , fd_(-1)
#endif
{
}

MemoryMappedFile::~MemoryMappedFile() {
    Close();
}

bool MemoryMappedFile::Open(const std::string& path) {
    Close();
    
#ifdef _WIN32
    // Windows implementation
    file_handle_ = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        file_handle_ = nullptr;
        return false;
    }
    
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file_handle_, &file_size)) {
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        return false;
    }
    size_ = static_cast<size_t>(file_size.QuadPart);
    
    if (size_ == 0) {
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        return false;
    }
    
    map_handle_ = CreateFileMapping(file_handle_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map_handle_) {
        CloseHandle(file_handle_);
        file_handle_ = nullptr;
        return false;
    }
    
    data_ = static_cast<uint8_t*>(MapViewOfFile(map_handle_, FILE_MAP_READ, 0, 0, 0));
    if (!data_) {
        CloseHandle(map_handle_);
        CloseHandle(file_handle_);
        map_handle_ = nullptr;
        file_handle_ = nullptr;
        return false;
    }
#else
    // POSIX implementation
    fd_ = open(path.c_str(), O_RDONLY);
    if (fd_ < 0) return false;
    
    struct stat st;
    if (fstat(fd_, &st) != 0) {
        close(fd_);
        fd_ = -1;
        return false;
    }
    size_ = st.st_size;
    
    if (size_ == 0) {
        close(fd_);
        fd_ = -1;
        return false;
    }
    
    data_ = static_cast<uint8_t*>(mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0));
    if (data_ == MAP_FAILED) {
        close(fd_);
        fd_ = -1;
        data_ = nullptr;
        return false;
    }
#endif
    
    return true;
}

void MemoryMappedFile::Close() {
    if (!data_) return;
    
#ifdef _WIN32
    UnmapViewOfFile(data_);
    if (map_handle_) CloseHandle(map_handle_);
    if (file_handle_) CloseHandle(file_handle_);
    map_handle_ = nullptr;
    file_handle_ = nullptr;
#else
    munmap(data_, size_);
    if (fd_ >= 0) close(fd_);
    fd_ = -1;
#endif
    
    data_ = nullptr;
    size_ = 0;
}

//=============================================================================
// GGUF Loader Implementation
//=============================================================================

GGUFLoader::GGUFLoader() 
    : loaded_(false), file_offset_(0), loaded_tensor_size_(0) {
    std::memset(&header_, 0, sizeof(header_));
}

GGUFLoader::~GGUFLoader() {
    Unload();
}

bool GGUFLoader::Load(const std::string& path) {
    Unload();
    
    path_ = path;
    
    // Open file via memory mapping
    if (!mmap_.Open(path)) {
        ReportError("Failed to open file: " + path);
        return false;
    }
    
    ReportProgress(10);
    
    // Parse header
    if (!ParseHeader()) {
        Unload();
        return false;
    }
    
    ReportProgress(30);
    
    // Parse metadata
    if (!ParseMetadata()) {
        Unload();
        return false;
    }
    
    ReportProgress(60);
    
    // Parse tensor info
    if (!ParseTensors()) {
        Unload();
        return false;
    }
    
    ReportProgress(100);
    
    loaded_ = true;
    return true;
}

bool GGUFLoader::LoadStreaming(const std::string& path) {
    // For now, same as Load - can be extended for true streaming
    return Load(path);
}

void GGUFLoader::Unload() {
    mmap_.Close();
    loaded_ = false;
    path_.clear();
    file_offset_ = 0;
    loaded_tensor_size_ = 0;
    std::memset(&header_, 0, sizeof(header_));
    metadata_.clear();
    tensors_.clear();
    tensor_map_.clear();
}

bool GGUFLoader::ParseHeader() {
    if (!mmap_.IsOpen()) return false;
    
    // Read magic
    header_.magic = mmap_.ReadAt<uint32_t>(0);
    if (header_.magic != GGUF_MAGIC) {
        ReportError("Invalid GGUF magic number");
        return false;
    }
    
    // Read version
    header_.version = mmap_.ReadAt<uint32_t>(4);
    if (header_.version != GGUF_VERSION_V3) {
        ReportError("Unsupported GGUF version: " + std::to_string(header_.version));
        return false;
    }
    
    // Read tensor count
    header_.tensor_count = mmap_.ReadAt<uint64_t>(8);
    
    // Read metadata KV count
    header_.metadata_kv_count = mmap_.ReadAt<uint64_t>(16);
    
    // Header is 24 bytes
    file_offset_ = 24;
    header_.metadata_offset = file_offset_;
    
    return true;
}

std::string GGUFLoader::ReadString() {
    uint64_t len = mmap_.ReadAt<uint64_t>(file_offset_);
    file_offset_ += 8;
    
    if (len == 0 || file_offset_ + len > mmap_.Size()) {
        return "";
    }
    
    std::string result;
    result.resize(len);
    const uint8_t* ptr = mmap_.PtrAt(file_offset_);
    if (ptr) {
        std::memcpy(&result[0], ptr, len);
    }
    file_offset_ += len;
    
    return result;
}

GGUFMetadataValue GGUFLoader::ReadMetadataValue(uint8_t type) {
    GGUFMetadataValue value;
    value.type = static_cast<GGUFType>(type);
    
    switch (value.type) {
        case GGUFType::UINT8:
            value.value.u8 = mmap_.ReadAt<uint8_t>(file_offset_);
            file_offset_ += 1;
            break;
        case GGUFType::INT8:
            value.value.i8 = mmap_.ReadAt<int8_t>(file_offset_);
            file_offset_ += 1;
            break;
        case GGUFType::UINT16:
            value.value.u16 = mmap_.ReadAt<uint16_t>(file_offset_);
            file_offset_ += 2;
            break;
        case GGUFType::INT16:
            value.value.i16 = mmap_.ReadAt<int16_t>(file_offset_);
            file_offset_ += 2;
            break;
        case GGUFType::UINT32:
            value.value.u32 = mmap_.ReadAt<uint32_t>(file_offset_);
            file_offset_ += 4;
            break;
        case GGUFType::INT32:
            value.value.i32 = mmap_.ReadAt<int32_t>(file_offset_);
            file_offset_ += 4;
            break;
        case GGUFType::UINT64:
            value.value.u64 = mmap_.ReadAt<uint64_t>(file_offset_);
            file_offset_ += 8;
            break;
        case GGUFType::INT64:
            value.value.i64 = mmap_.ReadAt<int64_t>(file_offset_);
            file_offset_ += 8;
            break;
        case GGUFType::FLOAT32:
            value.value.f32 = mmap_.ReadAt<float>(file_offset_);
            file_offset_ += 4;
            break;
        case GGUFType::FLOAT64:
            value.value.f64 = mmap_.ReadAt<double>(file_offset_);
            file_offset_ += 8;
            break;
        case GGUFType::BOOL:
            value.value.b = mmap_.ReadAt<uint8_t>(file_offset_) != 0;
            file_offset_ += 1;
            break;
        case GGUFType::STRING:
            value.str = ReadString();
            break;
        case GGUFType::ARRAY: {
            uint32_t arr_type = mmap_.ReadAt<uint32_t>(file_offset_);
            file_offset_ += 4;
            uint64_t arr_len = mmap_.ReadAt<uint64_t>(file_offset_);
            file_offset_ += 8;
            
            value.array.reserve(arr_len);
            for (uint64_t i = 0; i < arr_len; i++) {
                value.array.push_back(ReadMetadataValue(arr_type));
            }
            break;
        }
        default:
            break;
    }
    
    return value;
}

bool GGUFLoader::ParseMetadata() {
    for (uint64_t i = 0; i < header_.metadata_kv_count; i++) {
        std::string key = ReadString();
        if (key.empty()) {
            ReportError("Failed to read metadata key");
            return false;
        }
        
        uint32_t type = mmap_.ReadAt<uint32_t>(file_offset_);
        file_offset_ += 4;
        
        GGUFMetadataValue value = ReadMetadataValue(type);
        metadata_[key] = std::move(value);
    }
    
    return true;
}

bool GGUFLoader::ParseTensors() {
    tensors_.reserve(header_.tensor_count);
    
    for (uint64_t i = 0; i < header_.tensor_count; i++) {
        GGUFTensorInfo tensor;
        
        // Read name
        tensor.name = ReadString();
        if (tensor.name.empty()) {
            ReportError("Failed to read tensor name");
            return false;
        }
        
        // Read dimensions
        tensor.dimensions = mmap_.ReadAt<uint32_t>(file_offset_);
        file_offset_ += 4;
        
        // Read shape
        tensor.shape.resize(tensor.dimensions);
        for (uint32_t d = 0; d < tensor.dimensions; d++) {
            tensor.shape[d] = mmap_.ReadAt<uint64_t>(file_offset_);
            file_offset_ += 8;
        }
        
        // Read type
        tensor.type = mmap_.ReadAt<uint32_t>(file_offset_);
        file_offset_ += 4;
        
        // Read offset
        tensor.offset = mmap_.ReadAt<uint64_t>(file_offset_);
        file_offset_ += 8;
        
        // Calculate size (simplified - would need type size lookup)
        tensor.size = tensor.GetElementCount() * 4; // Assume float32 for now
        
        tensor_map_[tensor.name] = tensors_.size();
        tensors_.push_back(std::move(tensor));
    }
    
    return true;
}

bool GGUFLoader::HasMetadata(const std::string& key) const {
    return metadata_.find(key) != metadata_.end();
}

GGUFMetadataValue GGUFLoader::GetMetadata(const std::string& key) const {
    auto it = metadata_.find(key);
    if (it != metadata_.end()) return it->second;
    return GGUFMetadataValue();
}

std::string GGUFLoader::GetMetadataString(const std::string& key) const {
    auto it = metadata_.find(key);
    if (it != metadata_.end() && it->second.type == GGUFType::STRING) {
        return it->second.str;
    }
    return "";
}

int32_t GGUFLoader::GetMetadataInt(const std::string& key, int32_t default_val) const {
    auto it = metadata_.find(key);
    if (it != metadata_.end()) {
        switch (it->second.type) {
            case GGUFType::UINT8: return it->second.value.u8;
            case GGUFType::INT8: return it->second.value.i8;
            case GGUFType::UINT16: return it->second.value.u16;
            case GGUFType::INT16: return it->second.value.i16;
            case GGUFType::UINT32: return it->second.value.u32;
            case GGUFType::INT32: return it->second.value.i32;
            default: break;
        }
    }
    return default_val;
}

float GGUFLoader::GetMetadataFloat(const std::string& key, float default_val) const {
    auto it = metadata_.find(key);
    if (it != metadata_.end()) {
        if (it->second.type == GGUFType::FLOAT32) {
            return it->second.value.f32;
        } else if (it->second.type == GGUFType::FLOAT64) {
            return static_cast<float>(it->second.value.f64);
        }
    }
    return default_val;
}

const GGUFTensorInfo* GGUFLoader::GetTensor(const std::string& name) const {
    auto it = tensor_map_.find(name);
    if (it != tensor_map_.end()) {
        return &tensors_[it->second];
    }
    return nullptr;
}

const GGUFTensorInfo* GGUFLoader::GetTensor(size_t index) const {
    if (index < tensors_.size()) {
        return &tensors_[index];
    }
    return nullptr;
}

std::vector<uint8_t> GGUFLoader::LoadTensorData(const std::string& name) {
    const GGUFTensorInfo* tensor = GetTensor(name);
    if (!tensor) return {};
    return LoadTensorData(*tensor);
}

std::vector<uint8_t> GGUFLoader::LoadTensorData(const GGUFTensorInfo& tensor) {
    std::vector<uint8_t> data;
    data.resize(tensor.size);
    
    const uint8_t* src = mmap_.PtrAt(tensor.offset);
    if (src) {
        std::memcpy(data.data(), src, tensor.size);
        loaded_tensor_size_ += tensor.size;
    }
    
    return data;
}

std::string GGUFLoader::GetArchitecture() const {
    return GetMetadataString("general.architecture");
}

int32_t GGUFLoader::GetVocabSize() const {
    return GetMetadataInt("tokenizer.ggml.tokens", 0);
}

int32_t GGUFLoader::GetContextLength() const {
    return GetMetadataInt("llama.context_length", 0);
}

int32_t GGUFLoader::GetEmbeddingLength() const {
    return GetMetadataInt("llama.embedding_length", 0);
}

int32_t GGUFLoader::GetLayerCount() const {
    return GetMetadataInt("llama.block_count", 0);
}

std::string GGUFLoader::GetQuantization() const {
    return GetMetadataString("general.quantization_version");
}

size_t GGUFLoader::GetTotalTensorSize() const {
    size_t total = 0;
    for (const auto& t : tensors_) {
        total += t.size;
    }
    return total;
}

size_t GGUFLoader::GetLoadedTensorSize() const {
    return loaded_tensor_size_;
}

void GGUFLoader::ReportError(const std::string& msg) {
    if (on_error_) {
        on_error_(msg);
    }
}

void GGUFLoader::ReportProgress(int percent) {
    if (on_progress_) {
        on_progress_(percent);
    }
}

} // namespace RawrXD

