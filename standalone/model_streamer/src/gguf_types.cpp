#include "gguf_types.h"
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Model {

// ============================================================================
// MetadataEntry Implementation
// ============================================================================

std::string MetadataEntry::GetString() const {
    if (type != MetadataType::String || rawValue.size() < sizeof(uint64_t)) {
        return "";
    }
    uint64_t len;
    std::memcpy(&len, rawValue.data(), sizeof(len));
    if (len > rawValue.size() - sizeof(uint64_t)) {
        return "";
    }
    return std::string(reinterpret_cast<const char*>(rawValue.data() + sizeof(uint64_t)), len);
}

uint32_t MetadataEntry::GetUint32() const {
    if (type != MetadataType::Uint32 || rawValue.size() < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t value;
    std::memcpy(&value, rawValue.data(), sizeof(value));
    return value;
}

uint64_t MetadataEntry::GetUint64() const {
    if (type != MetadataType::Uint64 || rawValue.size() < sizeof(uint64_t)) {
        return 0;
    }
    uint64_t value;
    std::memcpy(&value, rawValue.data(), sizeof(value));
    return value;
}

float MetadataEntry::GetFloat32() const {
    if (type != MetadataType::Float32 || rawValue.size() < sizeof(float)) {
        return 0.0f;
    }
    float value;
    std::memcpy(&value, rawValue.data(), sizeof(value));
    return value;
}

bool MetadataEntry::GetBool() const {
    if (type != MetadataType::Bool || rawValue.size() < sizeof(uint8_t)) {
        return false;
    }
    return rawValue[0] != 0;
}

// ============================================================================
// ModelMetadata Implementation
// ============================================================================

std::string ModelMetadata::GetString(const std::string& key, const std::string& defaultVal) const {
    auto it = entries.find(key);
    if (it == entries.end()) return defaultVal;
    return it->second.GetString();
}

uint32_t ModelMetadata::GetUint32(const std::string& key, uint32_t defaultVal) const {
    auto it = entries.find(key);
    if (it == entries.end()) return defaultVal;
    return it->second.GetUint32();
}

uint64_t ModelMetadata::GetUint64(const std::string& key, uint64_t defaultVal) const {
    auto it = entries.find(key);
    if (it == entries.end()) return defaultVal;
    return it->second.GetUint64();
}

float ModelMetadata::GetFloat32(const std::string& key, float defaultVal) const {
    auto it = entries.find(key);
    if (it == entries.end()) return defaultVal;
    return it->second.GetFloat32();
}

bool ModelMetadata::GetBool(const std::string& key, bool defaultVal) const {
    auto it = entries.find(key);
    if (it == entries.end()) return defaultVal;
    return it->second.GetBool();
}

} // namespace Model
} // namespace RawrXD
