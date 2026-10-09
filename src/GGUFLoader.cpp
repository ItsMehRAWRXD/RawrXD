// ============================================================================
// GGUFLoader.cpp - Concrete GGUFLoader implementation
// ============================================================================

#include "GGUFLoader.h"
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <cstdint>

namespace RawrXD {

GGUFLoader::GGUFLoader() = default;
GGUFLoader::~GGUFLoader() = default;

bool GGUFLoader::Open(const std::string& path) {
    filepath_ = path;
    file_.open(path, std::ios::binary);
    return file_.is_open();
}

bool GGUFLoader::Close() {
    if (file_.is_open()) file_.close();
    return true;
}

bool GGUFLoader::ParseHeader() {
    if (!file_.is_open()) return false;
    
    uint32_t magic;
    file_.read(reinterpret_cast<char*>(&magic), 4);
    if (magic != 0x46554747) return false; // "GGUF"
    
    uint32_t version;
    file_.read(reinterpret_cast<char*>(&version), 4);
    
    uint64_t tensor_count, metadata_kv_count;
    file_.read(reinterpret_cast<char*>(&tensor_count), 8);
    file_.read(reinterpret_cast<char*>(&metadata_kv_count), 8);
    
    tensor_count_ = tensor_count;
    metadata_kv_count_ = metadata_kv_count;
    
    return true;
}

bool GGUFLoader::ParseMetadata() {
    if (!file_.is_open()) return false;
    
    for (uint64_t i = 0; i < metadata_kv_count_; ++i) {
        uint64_t key_len;
        file_.read(reinterpret_cast<char*>(&key_len), 8);
        std::string key(key_len, '\0');
        file_.read(&key[0], key_len);
        
        uint32_t value_type;
        file_.read(reinterpret_cast<char*>(&value_type), 4);
        
        if (value_type == 4) { // String
            uint64_t val_len;
            file_.read(reinterpret_cast<char*>(&val_len), 8);
            std::string val(val_len, '\0');
            file_.read(&val[0], val_len);
            metadata_kv_[key] = val;
        } else if (value_type == 3) { // uint32
            uint32_t val;
            file_.read(reinterpret_cast<char*>(&val), 4);
            metadata_kv_[key] = std::to_string(val);
        } else if (value_type == 5) { // uint64
            uint64_t val;
            file_.read(reinterpret_cast<char*>(&val), 8);
            metadata_kv_[key] = std::to_string(val);
        } else if (value_type == 8) { // array
            uint32_t array_type;
            uint64_t array_len;
            file_.read(reinterpret_cast<char*>(&array_type), 4);
            file_.read(reinterpret_cast<char*>(&array_len), 8);
            
            if (key == "tokenizer.ggml.tokens" && array_type == 8) {
                tokens_.reserve(array_len);
                for (uint64_t j = 0; j < array_len; ++j) {
                    uint64_t token_len;
                    file_.read(reinterpret_cast<char*>(&token_len), 8);
                    std::string token(token_len, '\0');
                    file_.read(&token[0], token_len);
                    tokens_.push_back(token);
                }
            } else {
                for (uint64_t j = 0; j < array_len; ++j) {
                    uint64_t item_len;
                    file_.read(reinterpret_cast<char*>(&item_len), 8);
                    file_.seekg(item_len, std::ios::cur);
                }
            }
        }
    }
    
    meta_.vocab_size = metadata_kv_.count("llama.vocab_size") ? std::stoi(metadata_kv_["llama.vocab_size"]) : 0;
    meta_.embedding_dim = metadata_kv_.count("llama.embedding_length") ? std::stoi(metadata_kv_["llama.embedding_length"]) : 0;
    meta_.layer_count = metadata_kv_.count("llama.block_count") ? std::stoi(metadata_kv_["llama.block_count"]) : 0;
    meta_.head_count = metadata_kv_.count("llama.attention.head_count") ? std::stoi(metadata_kv_["llama.attention.head_count"]) : 0;
    meta_.tokens = tokens_;
    meta_.token_scores.clear();
    meta_.token_types.clear();
    meta_.token_types_u32.clear();
    
    return true;
}

GGUFMetadata GGUFLoader::GetMetadata() const {
    return meta_;
}

GGUFHeader GGUFLoader::GetHeader() const {
    return GGUFHeader{0x46554747, 3, tensor_count_, metadata_kv_count_, 0};
}

std::vector<TensorInfo> GGUFLoader::GetTensorInfo() const {
    return std::vector<TensorInfo>{};
}

const std::vector<std::string>& GGUFLoader::GetVocabulary() const {
    return tokens_;
}

bool GGUFLoader::LoadTensorRange(size_t, size_t, std::vector<uint8_t>&) {
    return false; // Not implemented
}

size_t GGUFLoader::GetTensorByteSize(const TensorInfo&) const {
    return 0; // Not implemented
}

std::string GGUFLoader::GetTypeString(GGMLType) const {
    return ""; // Not implemented
}

bool GGUFLoader::BuildTensorIndex() {
    return false; // Not implemented
}

bool GGUFLoader::LoadZone(const std::string&, uint64_t) {
    return false; // Not implemented
}

bool GGUFLoader::UnloadZone(const std::string&) {
    return false; // Not implemented
}

bool GGUFLoader::LoadTensorZone(const std::string&, std::vector<uint8_t>&) {
    return false; // Not implemented
}

uint64_t GGUFLoader::GetFileSize() const {
    if (file_.is_open()) {
        auto pos = file_.tellg();
        file_.seekg(0, std::ios::end);
        uint64_t size = file_.tellg();
        file_.seekg(pos);
        return size;
    }
    return 0;
}

uint64_t GGUFLoader::GetCurrentMemoryUsage() const {
    return 0; // Not implemented
}

std::vector<std::string> GGUFLoader::GetLoadedZones() const {
    return {};
}

std::vector<std::string> GGUFLoader::GetAllZones() const {
    return {};
}

std::vector<TensorInfo> GGUFLoader::GetAllTensorInfo() const {
    return {};
}

} // namespace RawrXD