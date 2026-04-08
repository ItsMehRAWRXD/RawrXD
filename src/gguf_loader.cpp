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
        uint64_t val = (uint64_t)b[0] | ((uint64_t)b[1]<<8) | ((uint64_t)b[2]<<16) | ((uint64_t)b[3]<<24) |
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
        
        // --- HARDENED METADATA PARSER ---
        if (t == GGUF_TYPE_UINT32 || t == GGUF_TYPE_UINT64) {
            uint64_t v = 0; if (t == GGUF_TYPE_UINT32) { uint32_t v32; ReadValue(v32); v = v32; } else ReadValue(v);
            metadata_.kv_pairs[key] = std::to_string(v);
            // NOTE: Architecture-aware field resolution happens after the loop.
            // Do NOT assign metadata_ fields here via substring matching —
            // that incorrectly picks up .vision.* / .audio.* sub-component keys.
        } else if (t == GGUF_TYPE_STRING) {
            std::string val; ReadString(val); metadata_.kv_pairs[key] = val;
            if (key == "general.architecture") metadata_.architecture = val;
        } else if (t == GGUF_TYPE_ARRAY) {
            uint32_t ett; uint64_t el; ReadValue(ett); ReadValue(el);
            
            // SECURITY: Bounds check for massive arrays (e.g. tokenizer vocab)
            if (el > 2000000) {
                std::cerr << "[CRITICAL] GGUF Array size sanity check failed: " << el << " elements" << std::endl;
                return false;
            }

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
                // Skip unknown arrays to maintain offset alignment
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
            // Handle other scalar types to keep stream alignment
            uint8_t d8; uint16_t d16; uint32_t d32; uint64_t d64;
            switch(t) {
                case GGUF_TYPE_UINT8: case GGUF_TYPE_INT8: case GGUF_TYPE_BOOL: ReadValue(d8); break;
                case GGUF_TYPE_UINT16: case GGUF_TYPE_INT16: ReadValue(d16); break;
                case GGUF_TYPE_FLOAT32: case GGUF_TYPE_INT32: ReadValue(d32); break;
                case GGUF_TYPE_FLOAT64: case GGUF_TYPE_INT64: case GGUF_TYPE_UINT64: ReadValue(d64); break;
            }
        }
    }

    // --- Architecture-aware field resolution ---
    // Resolve config fields using exact architecture-prefixed keys from kv_pairs.
    // This avoids the old substring-matching bug that picked up .vision.* sub-component keys
    // (e.g., mistral3.vision.embedding_length overwriting mistral3.embedding_length).
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
        } else {
            // Fallback: no architecture key — scan kv_pairs for suffix matches,
            // but reject keys with .vision. / .audio. sub-components.
            for (const auto& kv : metadata_.kv_pairs) {
                const std::string& k = kv.first;
                if (k.find(".vision.") != std::string::npos || k.find(".audio.") != std::string::npos)
                    continue;
                uint32_t val = 0;
                try { val = static_cast<uint32_t>(std::stoull(kv.second)); } catch (...) { continue; }
                if (k.size() > 12 && k.compare(k.size() - 12, 12, ".block_count") == 0)
                    metadata_.layer_count = val;
                else if (k.size() > 15 && k.compare(k.size() - 15, 15, ".context_length") == 0)
                    metadata_.context_length = val;
                else if (k.size() > 17 && k.compare(k.size() - 17, 17, ".embedding_length") == 0)
                    metadata_.embedding_dim = val;
                else if (k.size() > 11 && k.compare(k.size() - 11, 11, ".vocab_size") == 0)
                    metadata_.vocab_size = val;
            }
        }
    }

    return true;
}

bool GGUFLoader::LoadTensorZone(const std::string&, std::vector<uint8_t>&) { return false; }
bool GGUFLoader::LoadTensorRange(size_t, size_t, std::vector<uint8_t>&) { return false; }
uint64_t GGUFLoader::GetFileSize() const { return 0; }
bool GGUFLoader::Load(VkDevice, VkPhysicalDevice) { return false; }
void GGUFLoader::CreateVulkanResources() {}
bool GGUFLoader::SetCompressionType(CompressionType) { return false; }
bool GGUFLoader::DecompressData(const std::vector<uint8_t>&, std::vector<uint8_t>&) { return false; }
bool GGUFLoader::CompressData(const std::vector<uint8_t>&, std::vector<uint8_t>&) { return false; }
bool GGUFLoader::HasUnsupportedQuantizationTypes() const { return false; }
std::vector<GGUFLoader::UnsupportedTypeInfo> GGUFLoader::GetUnsupportedQuantizationTypes() const { return {}; }
std::string GGUFLoader::GetRecommendedConversionType() const { return ""; }
size_t GGUFLoader::CalculateTensorSize(const std::vector<uint64_t>&, RawrXD::GGMLType) const { return 0; }
bool GGUFLoader::VerifyIntegrity(std::string*) { return true; }
bool GGUFLoader::RepairTrivialIssues(std::string*) { return true; }

