#include "gguf_loader.h"
#include "gguf_vocab_resolver.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <windows.h>

enum GGUFValueType : uint32_t {
    GGUF_TYPE_UINT8    = 0,
    GGUF_TYPE_INT8     = 1,
    GGUF_TYPE_UINT16   = 2,
    GGUF_TYPE_INT16    = 3,
    GGUF_TYPE_UINT32   = 4,
    GGUF_TYPE_INT32    = 5,
    GGUF_TYPE_FLOAT32  = 6,
    GGUF_TYPE_BOOL     = 7,
    GGUF_TYPE_STRING   = 8,
    GGUF_TYPE_ARRAY    = 9,
    GGUF_TYPE_UINT64   = 10,
    GGUF_TYPE_INT64    = 11,
    GGUF_TYPE_FLOAT64  = 12,
};

GGUFLoader::GGUFLoader() : is_open_(false) { std::memset(&header_, 0, sizeof(header_)); }
GGUFLoader::~GGUFLoader() { Close(); }

static uint32_t gu32(std::ifstream& f) {
    uint8_t b[4]; f.read((char*)b, 4);
    return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
}
static uint64_t gu64(std::ifstream& f) {
    uint8_t b[8]; f.read((char*)b, 8);
    return (uint64_t)b[0] | ((uint64_t)b[1]<<8) | ((uint64_t)b[2]<<16) | ((uint64_t)b[3]<<24) |
           ((uint64_t)b[4]<<32) | ((uint64_t)b[5]<<40) | ((uint64_t)b[6]<<48) | ((uint64_t)b[7]<<56);
}

bool GGUFLoader::Open(const std::string& filepath) {
    filepath_ = filepath;
    file_.open(filepath, std::ios::binary);
    if (!file_.is_open()) return false;
    is_open_ = true;
    try {
        if (!ParseHeader()) return false;
        if (!ParseMetadata()) return false;
        if (!BuildTensorIndex()) return false;
    } catch (...) { return false; }
    return true;
}

bool GGUFLoader::Close() { if (file_.is_open()) file_.close(); is_open_ = false; return true; }

bool GGUFLoader::ParseHeader() {
    file_.seekg(0);
    header_.magic = gu32(file_);
    if (header_.magic != 0x46554747) return false;
    header_.version = gu32(file_);
    header_.tensor_count = gu64(file_);
    header_.metadata_kv_count = gu64(file_);
    header_.metadata_offset = file_.tellg();
    return true;
}

bool GGUFLoader::ReadString(std::string& value) {
    uint64_t len = gu64(file_);
    if (len > 1024*1024) return false;
    value.resize(len); file_.read(&value[0], len);
    return file_.good();
}

template<typename T> bool GGUFLoader::ReadValue(T& v) {
    if (sizeof(T) == 4) {
        uint8_t b[4]; file_.read((char*)b, 4);
        uint32_t val = (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
        std::memcpy(&v, &val, 4);
    } else if (sizeof(T) == 8) {
        uint8_t b[8]; file_.read((char*)b, 8);
        uint64_t val = (uint64_t)b[0] | ((uint64_t)b[1]<<8) | ((uint64_t)b[2]<<16) | ((uint32_t)b[3]<<24) |
                       ((uint64_t)b[4]<<32) | ((uint64_t)b[5]<<40) | ((uint64_t)b[6]<<48) | ((uint64_t)b[7]<<56);
        std::memcpy(&v, &val, 8);
    } else {
        file_.read((char*)&v, sizeof(T));
    }
    return file_.good();
}

bool GGUFLoader::ParseMetadata() {
    file_.seekg(header_.metadata_offset);
    for (uint64_t i=0; i<header_.metadata_kv_count; ++i) {
        std::string key; if (!ReadString(key)) return false;
        uint32_t t; ReadValue(t);
        
        if (t == GGUF_TYPE_UINT32 || t == GGUF_TYPE_UINT64) {
            uint64_t v = 0; if (t == GGUF_TYPE_UINT32) { uint32_t v32; ReadValue(v32); v = v32; } else ReadValue(v);
            metadata_.kv_pairs[key] = std::to_string(v);
        } else if (t == GGUF_TYPE_STRING) {
            std::string val; ReadString(val); metadata_.kv_pairs[key] = val;
            if (key == "general.architecture") metadata_.architecture = val;
        } else if (t == GGUF_TYPE_ARRAY) {
            uint32_t ett; uint64_t el; ReadValue(ett); ReadValue(el);
            if (el > 2000000) return false;
            
            if (key == "tokenizer.ggml.tokens") {
                metadata_.tokens.reserve(el);
                for (uint64_t j=0; j<el; ++j) {
                    std::string s; if (ReadString(s)) metadata_.tokens.push_back(s);
                }
            } else if (key == "tokenizer.ggml.scores") {
                metadata_.token_scores.reserve(el);
                for (uint64_t j=0; j<el; ++j) {
                    float f; if (ReadValue(f)) metadata_.token_scores.push_back(f);
                }
            } else if (key == "tokenizer.ggml.token_type") {
                metadata_.token_types.reserve(el);
                for (uint64_t j=0; j<el; ++j) {
                    uint32_t u; if (ReadValue(u)) metadata_.token_types.push_back(u);
                }
            } else {
                for (uint64_t j=0; j<el; ++j) {
                    if (ett == GGUF_TYPE_STRING) { std::string s; ReadString(s); }
                    else if (ett == GGUF_TYPE_FLOAT32) { float f; ReadValue(f); }
                    else if (ett == GGUF_TYPE_UINT32) { uint32_t u; ReadValue(u); }
                    else if (ett == GGUF_TYPE_UINT64) { uint64_t u; ReadValue(u); }
                    else if (ett == GGUF_TYPE_INT32) { int32_t i32; ReadValue(i32); }
                    else if (ett == GGUF_TYPE_BOOL) { uint8_t b; ReadValue(b); }
                }
            }
        } else {
            uint8_t d8; uint16_t d16; uint32_t d32; uint64_t d64;
            switch(t) {
                case GGUF_TYPE_UINT8: case GGUF_TYPE_INT8: case GGUF_TYPE_BOOL: ReadValue(d8); break;
                case GGUF_TYPE_UINT16: case GGUF_TYPE_INT16: ReadValue(d16); break;
                case GGUF_TYPE_FLOAT32: case GGUF_TYPE_INT32: ReadValue(d32); break;
                case GGUF_TYPE_FLOAT64: case GGUF_TYPE_INT64: case GGUF_TYPE_UINT64: ReadValue(d64); break;
            }
        }
    }

    tensor_info_offset = file_.tellg();

    {
        const auto tryResolveU32 = [&](const std::string& exactKey, uint32_t& field) {
            auto it = metadata_.kv_pairs.find(exactKey);
            if (it != metadata_.kv_pairs.end()) {
                try { field = static_cast<uint32_t>(std::stoull(it->second)); } catch (...) {}
            }
        };

        if (!metadata_.architecture.empty()) {
            const std::string& arch = metadata_.architecture;
            tryResolveU32(arch + ".block_count",    metadata_.layer_count);
            tryResolveU32(arch + ".context_length",  metadata_.context_length);
            tryResolveU32(arch + ".embedding_length", metadata_.embedding_dim);
            tryResolveU32(arch + ".vocab_size",      metadata_.vocab_size);
            tryResolveU32(arch + ".attention.head_count", metadata_.head_count);
        }
    }

    return true;
}

bool GGUFLoader::LoadZone(const std::string&, uint64_t) { return true; }
bool GGUFLoader::UnloadZone(const std::string&) { return true; }

bool GGUFLoader::LoadTensorRange(size_t start, size_t count, std::vector<uint8_t>& data) {
    if (start + count > tensors_.size()) return false;
    uint64_t total_size = 0;
    for (size_t i = start; i < start + count; ++i) total_size += tensors_[i].size;
    
    data.resize(total_size);
    uint8_t* ptr = data.data();
    for (size_t i = start; i < start + count; ++i) {
        file_.clear();
        file_.seekg(data_base_offset + tensors_[i].offset, std::ios::beg);
        file_.read(reinterpret_cast<char*>(ptr), tensors_[i].size);
        ptr += tensors_[i].size;
    }
    return true;
}

bool GGUFLoader::LoadTensorZone(const std::string& name, std::vector<uint8_t>& data) {
    auto it = std::find_if(tensors_.begin(), tensors_.end(), [&](const RawrXD::TensorInfo& t){ return t.name == name; });
    if (it == tensors_.end()) return false;
    
    file_.clear();
    file_.seekg(data_base_offset + it->offset, std::ios::beg);
    data.resize(it->size);
    file_.read(reinterpret_cast<char*>(data.data()), it->size);
    return file_.good();
}

uint64_t GGUFLoader::GetFileSize() const {
    if (!filepath_.empty()) {
        WIN32_FILE_ATTRIBUTE_DATA attr;
        if (GetFileAttributesExA(filepath_.c_str(), GetFileExInfoStandard, &attr)) {
            return (static_cast<uint64_t>(attr.nFileSizeHigh) << 32) | attr.nFileSizeLow;
        }
    }
    return 0;
}

void GGUFLoader::CreateVulkanResources() {}

bool GGUFLoader::Load(VkDevice vkDevice, VkPhysicalDevice vkPhysDevice) {
    if (!is_open_) return false;
    device = vkDevice; physDevice = vkPhysDevice;
    if (tensors_.empty()) { if (!BuildTensorIndex()) return false; }
    CreateVulkanResources();

    hFile = CreateFileA(filepath_.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER liSize; GetFileSizeEx(hFile, &liSize); fileSize = liSize.QuadPart;
    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) { CloseHandle(hFile); return false; }
    mappedView = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!mappedView) { CloseHandle(hMapping); CloseHandle(hFile); return false; }

    BeginCommandBuffer();
    for (auto& info : tensors_) { LoadTensorAsync(info); }
    EndCommandBuffer();

    UnmapViewOfFile(mappedView); CloseHandle(hMapping); CloseHandle(hFile);
    mappedView = nullptr; hMapping = nullptr; hFile = INVALID_HANDLE_VALUE;
    return true;
}

void GGUFLoader::LoadTensorAsync(RawrXD::TensorInfo& info) {
    // uint8_t* src = (uint8_t*)mappedView + data_base_offset + info.offset;
}

void GGUFLoader::BeginCommandBuffer() {}
void GGUFLoader::EndCommandBuffer() {}
uint32_t GGUFLoader::FindMemoryType(uint32_t, uint32_t) { return 0; }
uint32_t GGUFLoader::FindQueueFamilyIndex(VkPhysicalDevice, uint32_t) { return 0; }
void GGUFLoader::UploadF32(RawrXD::TensorInfo&, void*, size_t) {}
void GGUFLoader::DequantAndUploadQ4_0(RawrXD::TensorInfo&, void*, size_t) {}

bool GGUFLoader::SetCompressionType(CompressionType) { return false; }
bool GGUFLoader::DecompressData(const std::vector<uint8_t>&, std::vector<uint8_t>&) { return false; }
bool GGUFLoader::CompressData(const std::vector<uint8_t>&, std::vector<uint8_t>&) { return false; }
bool GGUFLoader::HasUnsupportedQuantizationTypes() const { return false; }
std::vector<GGUFLoader::UnsupportedTypeInfo> GGUFLoader::GetUnsupportedQuantizationTypes() const { return {}; }
std::string GGUFLoader::GetRecommendedConversionType() const { return ""; }

size_t GGUFLoader::CalculateTensorSize(const std::vector<uint64_t>& shape, RawrXD::GGMLType type) const {
    if (shape.empty()) return 0;
    size_t el = 1; for (auto d : shape) el *= d;
    switch (type) {
        case RawrXD::GGMLType::F32:  return el * 4;
        case RawrXD::GGMLType::F16:  return el * 2;
        case RawrXD::GGMLType::Q4_0: return el / 2 + (el / 32) * 2;
        case RawrXD::GGMLType::Q4_1: return el / 2 + (el / 32) * 2 + 4;
        case RawrXD::GGMLType::Q8_0: return el + (el / 32) * 2;
        default: return el * 4;
    }
}

bool GGUFLoader::BuildTensorIndex() {
    if (!file_.is_open() || tensor_info_offset == 0) return false;
    file_.seekg(tensor_info_offset);
    tensors_.clear();
    for (uint64_t i = 0; i < header_.tensor_count; ++i) {
        RawrXD::TensorInfo info;
        if (!ReadString(info.name)) return false;
        uint32_t n_dims; ReadValue(n_dims);
        info.shape.resize(n_dims);
        for (uint32_t d=0; d<n_dims; ++d) ReadValue(info.shape[d]);
        uint32_t type_val; ReadValue(type_val);
        info.type = static_cast<RawrXD::GGMLType>(type_val);
        ReadValue(info.offset);
        info.size = CalculateTensorSize(info.shape, info.type);
        info.size_bytes = info.size;
        tensors_.push_back(info);
    }
    uint64_t alignment = 32;
    auto it = metadata_.kv_pairs.find("general.alignment");
    if (it != metadata_.kv_pairs.end()) { try { alignment = std::stoull(it->second); } catch(...) {} }
    uint64_t cur = file_.tellg();
    data_base_offset = (cur % alignment == 0) ? cur : (cur + (alignment - (cur % alignment)));
    return true;
}

bool GGUFLoader::VerifyIntegrity(std::string*) { return true; }
bool GGUFLoader::RepairTrivialIssues(std::string*) { return true; }
