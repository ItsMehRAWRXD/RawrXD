#pragma once
#ifndef RAWRXD_GGUF_METADATA_READER_HPP
#define RAWRXD_GGUF_METADATA_READER_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <memory>
#include <iostream>

namespace RawrXD {

// ============================================================================
// GGUF File Format Structures
// Based on GGUF spec: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
// ============================================================================

enum class GGUFValueType : uint32_t {
    UINT8 = 0,
    INT8 = 1,
    UINT16 = 2,
    INT16 = 3,
    UINT32 = 4,
    INT32 = 5,
    FLOAT32 = 6,
    BOOL = 7,
    STRING = 8,
    ARRAY = 9,
    UINT64 = 10,
    INT64 = 11,
    FLOAT64 = 12
};

struct GGUFMetadataKV {
    std::string key;
    GGUFValueType type;
    std::vector<uint8_t> raw_value;
    
    // Typed accessors
    std::string AsString() const;
    uint32_t AsUInt32() const;
    int32_t AsInt32() const;
    float AsFloat() const;
    bool AsBool() const;
};

struct GGUFMetadata {
    uint32_t version = 0;
    uint64_t tensor_count = 0;
    uint64_t metadata_kv_count = 0;
    std::map<std::string, GGUFMetadataKV> metadata;
    
    // Common metadata accessors
    std::string GetString(const std::string& key, const std::string& default_val = "") const;
    uint32_t GetUInt32(const std::string& key, uint32_t default_val = 0) const;
    std::string GetArchitecture() const;
    std::string GetChatTemplate() const;
    bool HasChatTemplate() const;
    uint32_t GetBOSToken() const;
    uint32_t GetEOSToken() const;
    
    // RawrXD custom metadata
    std::string GetPromptStyle() const;  // "raw_bos", "chatml", etc.
    std::string GetOutputParser() const; // "text_markers", "plain", etc.
};

// ============================================================================
// GGUF Metadata Reader
// ============================================================================
class GGUFMetadataReader {
public:
    // Read metadata from GGUF file
    static bool Read(const std::string& filepath, GGUFMetadata& out_metadata);
    
    // Quick check if file is valid GGUF
    static bool IsValidGGUF(const std::string& filepath);
    
    // Print metadata for debugging
    static void PrintMetadata(const GGUFMetadata& metadata, std::ostream& os = std::cout);

private:
    static bool ReadHeader(std::ifstream& file, GGUFMetadata& metadata);
    static bool ReadMetadataKV(std::ifstream& file, GGUFMetadataKV& kv);
    static std::string ReadString(std::ifstream& file);
    static uint32_t ReadUInt32(std::ifstream& file);
    static uint64_t ReadUInt64(std::ifstream& file);
};

// ============================================================================
// Implementation
// ============================================================================

inline std::string GGUFMetadataKV::AsString() const {
    if (type != GGUFValueType::STRING || raw_value.size() < 4) return "";
    uint32_t len = *reinterpret_cast<const uint32_t*>(raw_value.data());
    if (raw_value.size() < 4 + len) return "";
    return std::string(reinterpret_cast<const char*>(raw_value.data() + 4), len);
}

inline uint32_t GGUFMetadataKV::AsUInt32() const {
    if (type != GGUFValueType::UINT32 || raw_value.size() < 4) return 0;
    return *reinterpret_cast<const uint32_t*>(raw_value.data());
}

inline int32_t GGUFMetadataKV::AsInt32() const {
    if (type != GGUFValueType::INT32 || raw_value.size() < 4) return 0;
    return *reinterpret_cast<const int32_t*>(raw_value.data());
}

inline float GGUFMetadataKV::AsFloat() const {
    if (type != GGUFValueType::FLOAT32 || raw_value.size() < 4) return 0.0f;
    return *reinterpret_cast<const float*>(raw_value.data());
}

inline bool GGUFMetadataKV::AsBool() const {
    if (type != GGUFValueType::BOOL || raw_value.size() < 1) return false;
    return raw_value[0] != 0;
}

inline std::string GGUFMetadata::GetString(const std::string& key, const std::string& default_val) const {
    auto it = metadata.find(key);
    if (it != metadata.end()) return it->second.AsString();
    return default_val;
}

inline uint32_t GGUFMetadata::GetUInt32(const std::string& key, uint32_t default_val) const {
    auto it = metadata.find(key);
    if (it != metadata.end()) return it->second.AsUInt32();
    return default_val;
}

inline std::string GGUFMetadata::GetArchitecture() const {
    return GetString("general.architecture", "unknown");
}

inline std::string GGUFMetadata::GetChatTemplate() const {
    return GetString("tokenizer.chat_template", "");
}

inline bool GGUFMetadata::HasChatTemplate() const {
    return !GetChatTemplate().empty();
}

inline uint32_t GGUFMetadata::GetBOSToken() const {
    return GetUInt32("tokenizer.ggml.bos_token_id", 1);
}

inline uint32_t GGUFMetadata::GetEOSToken() const {
    return GetUInt32("tokenizer.ggml.eos_token_id", 2);
}

inline std::string GGUFMetadata::GetPromptStyle() const {
    // First check for RawrXD custom metadata
    std::string custom = GetString("rawrxd.prompt_style", "");
    if (!custom.empty()) return custom;
    
    // Otherwise infer from chat template
    std::string chat_template = GetChatTemplate();
    if (chat_template.empty()) return "raw_bos";
    
    if (chat_template.find("[INST]") != std::string::npos) return "mistral_llama2";
    if (chat_template.find("<|user|>") != std::string::npos) return "phi3";
    if (chat_template.find("<|begin_of_text|>") != std::string::npos) return "llama3";
    if (chat_template.find("<|im_start|>") != std::string::npos) return "chatml";
    if (chat_template.find("{{prompt}}") != std::string::npos) return "raw_bos";
    
    return "generic";
}

inline std::string GGUFMetadata::GetOutputParser() const {
    std::string custom = GetString("rawrxd.output_parser", "");
    if (!custom.empty()) return custom;
    
    // Infer from model name or architecture
    std::string name = GetString("general.name", "");
    if (name.find("bigdaddyg") != std::string::npos || 
        name.find("BigDaddyG") != std::string::npos) {
        return "text_markers";
    }
    
    return "plain";
}

// ============================================================================
// Reader Implementation
// ============================================================================
inline bool GGUFMetadataReader::IsValidGGUF(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return false;
    
    char magic[4];
    file.read(magic, 4);
    return (magic[0] == 'G' && magic[1] == 'G' && magic[2] == 'U' && magic[3] == 'F');
}

inline bool GGUFMetadataReader::Read(const std::string& filepath, GGUFMetadata& out_metadata) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open: " << filepath << std::endl;
        return false;
    }
    
    // Check magic
    char magic[4];
    file.read(magic, 4);
    if (magic[0] != 'G' || magic[1] != 'G' || magic[2] != 'U' || magic[3] != 'F') {
        std::cerr << "Invalid GGUF magic" << std::endl;
        return false;
    }
    
    // Read version
    out_metadata.version = ReadUInt32(file);
    if (out_metadata.version < 2 && out_metadata.version > 3) {
        std::cerr << "Unsupported GGUF version: " << out_metadata.version << std::endl;
        return false;
    }
    
    // Read tensor count and metadata KV count
    out_metadata.tensor_count = ReadUInt64(file);
    out_metadata.metadata_kv_count = ReadUInt64(file);
    
    // Read metadata key-value pairs
    for (uint64_t i = 0; i < out_metadata.metadata_kv_count; i++) {
        GGUFMetadataKV kv;
        if (!ReadMetadataKV(file, kv)) {
            std::cerr << "Failed to read metadata KV " << i << std::endl;
            return false;
        }
        out_metadata.metadata[kv.key] = std::move(kv);
    }
    
    return true;
}

inline bool GGUFMetadataReader::ReadMetadataKV(std::ifstream& file, GGUFMetadataKV& kv) {
    // Read key (string)
    kv.key = ReadString(file);
    if (kv.key.empty()) return false;
    
    // Read value type
    uint32_t type_val = ReadUInt32(file);
    kv.type = static_cast<GGUFValueType>(type_val);
    
    // Read value based on type
    switch (kv.type) {
        case GGUFValueType::UINT8:
        case GGUFValueType::INT8:
        case GGUFValueType::BOOL:
            kv.raw_value.resize(1);
            file.read(reinterpret_cast<char*>(kv.raw_value.data()), 1);
            break;
            
        case GGUFValueType::UINT16:
        case GGUFValueType::INT16:
            kv.raw_value.resize(2);
            file.read(reinterpret_cast<char*>(kv.raw_value.data()), 2);
            break;
            
        case GGUFValueType::UINT32:
        case GGUFValueType::INT32:
        case GGUFValueType::FLOAT32:
            kv.raw_value.resize(4);
            file.read(reinterpret_cast<char*>(kv.raw_value.data()), 4);
            break;
            
        case GGUFValueType::UINT64:
        case GGUFValueType::INT64:
        case GGUFValueType::FLOAT64:
            kv.raw_value.resize(8);
            file.read(reinterpret_cast<char*>(kv.raw_value.data()), 8);
            break;
            
        case GGUFValueType::STRING: {
            std::string str = ReadString(file);
            kv.raw_value.resize(4 + str.size());
            *reinterpret_cast<uint32_t*>(kv.raw_value.data()) = static_cast<uint32_t>(str.size());
            std::memcpy(kv.raw_value.data() + 4, str.data(), str.size());
            break;
        }
            
        case GGUFValueType::ARRAY:
            // Skip arrays for now (complex)
            return false;
            
        default:
            return false;
    }
    
    return file.good();
}

inline std::string GGUFMetadataReader::ReadString(std::ifstream& file) {
    uint32_t len = ReadUInt32(file);
    if (len == 0 || len > 1000000) return ""; // Sanity check
    
    std::string str(len, '\0');
    file.read(&str[0], len);
    return str;
}

inline uint32_t GGUFMetadataReader::ReadUInt32(std::ifstream& file) {
    uint32_t val = 0;
    file.read(reinterpret_cast<char*>(&val), 4);
    return val;
}

inline uint64_t GGUFMetadataReader::ReadUInt64(std::ifstream& file) {
    uint64_t val = 0;
    file.read(reinterpret_cast<char*>(&val), 8);
    return val;
}

inline void GGUFMetadataReader::PrintMetadata(const GGUFMetadata& metadata, std::ostream& os) {
    os << "GGUF Version: " << metadata.version << std::endl;
    os << "Tensor Count: " << metadata.tensor_count << std::endl;
    os << "Metadata KV Count: " << metadata.metadata_kv_count << std::endl;
    os << "\n=== Metadata ===" << std::endl;
    
    for (const auto& [key, kv] : metadata.metadata) {
        os << key << " (type " << static_cast<uint32_t>(kv.type) << "): ";
        
        switch (kv.type) {
            case GGUFValueType::STRING:
                os << "\"" << kv.AsString() << "\"";
                break;
            case GGUFValueType::UINT32:
                os << kv.AsUInt32();
                break;
            case GGUFValueType::INT32:
                os << kv.AsInt32();
                break;
            case GGUFValueType::FLOAT32:
                os << kv.AsFloat();
                break;
            case GGUFValueType::BOOL:
                os << (kv.AsBool() ? "true" : "false");
                break;
            default:
                os << "[binary data]";
        }
        os << std::endl;
    }
    
    os << "\n=== Inferred Settings ===" << std::endl;
    os << "Architecture: " << metadata.GetArchitecture() << std::endl;
    os << "Chat Template: " << (metadata.HasChatTemplate() ? "Yes" : "No") << std::endl;
    if (metadata.HasChatTemplate()) {
        os << "Template: " << metadata.GetChatTemplate().substr(0, 100) << "..." << std::endl;
    }
    os << "Prompt Style: " << metadata.GetPromptStyle() << std::endl;
    os << "Output Parser: " << metadata.GetOutputParser() << std::endl;
    os << "BOS Token: " << metadata.GetBOSToken() << std::endl;
    os << "EOS Token: " << metadata.GetEOSToken() << std::endl;
}

} // namespace RawrXD

#endif // RAWRXD_GGUF_METADATA_READER_HPP
