#include "UnifiedConfig.hpp"
#include <windows.h>
#include <cstring>
#include <cstdlib>
#include <cctype>

namespace RawrXD {

static UnifiedConfig* g_globalConfig = nullptr;

UnifiedConfig* GetGlobalConfig() noexcept {
    return g_globalConfig;
}

void SetGlobalConfig(UnifiedConfig* config) noexcept {
    g_globalConfig = config;
}

UnifiedConfig::UnifiedConfig() noexcept
    : m_hFile(nullptr)
    , m_hMapping(nullptr)
    , m_data(nullptr)
    , m_dataSize(0)
    , m_lastError("")
{
}

UnifiedConfig::~UnifiedConfig() {
    Unload();
}

bool UnifiedConfig::LoadFromFile(const wchar_t* filePath) noexcept {
    Unload();
    
    // Open file
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        m_lastError = "Failed to open file";
        return false;
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        m_lastError = "Failed to get file size";
        return false;
    }
    
    // Create file mapping
    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        m_lastError = "Failed to create file mapping";
        return false;
    }
    
    // Map view
    const char* data = static_cast<const char*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
    if (!data) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        m_lastError = "Failed to map view";
        return false;
    }
    
    m_hFile = hFile;
    m_hMapping = hMapping;
    m_data = data;
    m_dataSize = static_cast<size_t>(fileSize.QuadPart);
    
    // Set as global config
    if (!g_globalConfig) {
        SetGlobalConfig(this);
    }
    
    return true;
}

bool UnifiedConfig::LoadFromString(std::string_view json) noexcept {
    Unload();
    
    m_data = json.data();
    m_dataSize = json.length();
    
    // Validate it's at least parseable
    ConfigValue root;
    const char* end = m_data + m_dataSize;
    if (!ParseValue(m_data, end, root)) {
        m_data = nullptr;
        m_dataSize = 0;
        return false;
    }
    
    // Set as global config
    if (!g_globalConfig) {
        SetGlobalConfig(this);
    }
    
    return true;
}

bool UnifiedConfig::Reload() noexcept {
    // For memory-mapped files, just re-parse
    // In production, would atomically swap pointers
    return IsLoaded();
}

void UnifiedConfig::Unload() noexcept {
    if (g_globalConfig == this) {
        SetGlobalConfig(nullptr);
    }
    
    if (m_data && m_hMapping) {
        UnmapViewOfFile(m_data);
    }
    if (m_hMapping) {
        CloseHandle(m_hMapping);
    }
    if (m_hFile) {
        CloseHandle(m_hFile);
    }
    
    m_hFile = nullptr;
    m_hMapping = nullptr;
    m_data = nullptr;
    m_dataSize = 0;
}

// --- Value Access ---

ConfigValue UnifiedConfig::Get(std::string_view keyPath) const noexcept {
    if (!m_data) return {ConfigValueType::Null};
    
    const char* ptr = m_data;
    const char* end = m_data + m_dataSize;
    
    // Skip to root object
    ptr = SkipWhitespace(ptr, end);
    if (ptr >= end || *ptr != '{') return {ConfigValueType::Null};
    ++ptr; // Skip '{'
    
    // Parse path segments
    size_t start = 0;
    while (start < keyPath.length()) {
        size_t sep = keyPath.find('/', start);
        std::string_view key = (sep == std::string_view::npos) 
            ? keyPath.substr(start) 
            : keyPath.substr(start, sep - start);
        
        // Find key in current object
        ptr = FindKey(ptr, end, key);
        if (!ptr) return {ConfigValueType::Null};
        
        // Parse the value
        ConfigValue value;
        ptr = ParseValue(ptr, end, value);
        if (!ptr) return {ConfigValueType::Null};
        
        // If more path segments, value must be object
        if (sep != std::string_view::npos) {
            if (value.type != ConfigValueType::Object) {
                return {ConfigValueType::Null};
            }
            // Continue into object
            start = sep + 1;
        } else {
            // Final value
            return value;
        }
    }
    
    return {ConfigValueType::Null};
}

bool UnifiedConfig::GetBool(std::string_view keyPath, bool defaultValue) const noexcept {
    auto val = Get(keyPath);
    return val.IsBool() ? val.AsBool() : defaultValue;
}

int64_t UnifiedConfig::GetInt(std::string_view keyPath, int64_t defaultValue) const noexcept {
    auto val = Get(keyPath);
    return val.IsInt() ? val.AsInt() : defaultValue;
}

double UnifiedConfig::GetFloat(std::string_view keyPath, double defaultValue) const noexcept {
    auto val = Get(keyPath);
    return val.IsFloat() ? val.AsFloat() : defaultValue;
}

std::string_view UnifiedConfig::GetString(std::string_view keyPath, std::string_view defaultValue) const noexcept {
    auto val = Get(keyPath);
    return val.IsString() ? val.AsString() : defaultValue;
}

bool UnifiedConfig::HasKey(std::string_view keyPath) const noexcept {
    return !Get(keyPath).IsNull();
}

size_t UnifiedConfig::GetKeys(std::string_view path, std::string_view* outKeys, size_t maxCount) const noexcept {
    // Simplified implementation - would enumerate object keys
    // For now, return 0 (stub)
    return 0;
}

bool UnifiedConfig::Validate() const noexcept {
    // Simplified validation - check basic structure
    if (!m_data) return false;
    
    const char* end = m_data + m_dataSize;
    const char* ptr = SkipWhitespace(m_data, end);
    
    // Must start with '{' or '['
    if (ptr >= end || (*ptr != '{' && *ptr != '[')) {
        m_lastError = "Invalid JSON root";
        return false;
    }
    
    return true;
}

std::string_view UnifiedConfig::GetRawData() const noexcept {
    if (!m_data) return {};
    return std::string_view(m_data, m_dataSize);
}

// --- Internal Parsing ---

const char* UnifiedConfig::ParseValue(const char* ptr, const char* end, ConfigValue& outValue) const noexcept {
    ptr = SkipWhitespace(ptr, end);
    if (ptr >= end) return nullptr;
    
    switch (*ptr) {
        case '"':
            outValue.type = ConfigValueType::String;
            return ParseString(ptr, end, outValue.stringValue);
            
        case '{':
            outValue.type = ConfigValueType::Object;
            // Skip object content for now (simplified)
            outValue.stringValue = std::string_view(ptr, 1);
            return ptr + 1;
            
        case '[':
            outValue.type = ConfigValueType::Array;
            outValue.stringValue = std::string_view(ptr, 1);
            return ptr + 1;
            
        case 't':
        case 'f':
            outValue.type = ConfigValueType::Boolean;
            outValue.boolValue = (*ptr == 't');
            // Skip "true" or "false"
            while (ptr < end && std::isalpha(*ptr)) ++ptr;
            return ptr;
            
        case 'n':
            outValue.type = ConfigValueType::Null;
            // Skip "null"
            while (ptr < end && std::isalpha(*ptr)) ++ptr;
            return ptr;
            
        case '-':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return ParseNumber(ptr, end, outValue);
            
        default:
            return nullptr;
    }
}

const char* UnifiedConfig::ParseString(const char* ptr, const char* end, std::string_view& outString) const noexcept {
    if (ptr >= end || *ptr != '"') return nullptr;
    ++ptr; // Skip opening quote
    
    const char* start = ptr;
    while (ptr < end && *ptr != '"') {
        if (*ptr == '\\' && ptr + 1 < end) {
            ptr += 2; // Skip escaped char
        } else {
            ++ptr;
        }
    }
    
    outString = std::string_view(start, ptr - start);
    
    if (ptr < end && *ptr == '"') ++ptr; // Skip closing quote
    return ptr;
}

const char* UnifiedConfig::ParseNumber(const char* ptr, const char* end, ConfigValue& outValue) const noexcept {
    const char* start = ptr;
    bool isFloat = false;
    
    if (ptr < end && *ptr == '-') ++ptr;
    
    while (ptr < end && std::isdigit(*ptr)) ++ptr;
    
    if (ptr < end && *ptr == '.') {
        isFloat = true;
        ++ptr;
        while (ptr < end && std::isdigit(*ptr)) ++ptr;
    }
    
    if (ptr < end && (*ptr == 'e' || *ptr == 'E')) {
        isFloat = true;
        ++ptr;
        if (ptr < end && (*ptr == '+' || *ptr == '-')) ++ptr;
        while (ptr < end && std::isdigit(*ptr)) ++ptr;
    }
    
    std::string_view numStr(start, ptr - start);
    
    if (isFloat) {
        outValue.type = ConfigValueType::Float;
        outValue.floatValue = std::atof(numStr.data());
    } else {
        outValue.type = ConfigValueType::Integer;
        outValue.intValue = std::atoll(numStr.data());
    }
    
    return ptr;
}

const char* UnifiedConfig::SkipWhitespace(const char* ptr, const char* end) const noexcept {
    while (ptr < end && std::isspace(*ptr)) ++ptr;
    return ptr;
}

const char* UnifiedConfig::FindKey(const char* ptr, const char* end, std::string_view key) const noexcept {
    while (ptr < end) {
        ptr = SkipWhitespace(ptr, end);
        if (ptr >= end) return nullptr;
        
        if (*ptr == '"') {
            std::string_view foundKey;
            ptr = ParseString(ptr, end, foundKey);
            if (!ptr) return nullptr;
            
            ptr = SkipWhitespace(ptr, end);
            if (ptr < end && *ptr == ':') {
                ++ptr; // Skip ':'
                
                if (foundKey == key) {
                    return ptr;
                }
                
                // Skip value
                ConfigValue val;
                ptr = ParseValue(ptr, end, val);
                if (!ptr) return nullptr;
            }
        } else if (*ptr == '}') {
            return nullptr; // Key not found
        } else {
            ++ptr;
        }
        
        ptr = SkipWhitespace(ptr, end);
        if (ptr < end && *ptr == ',') ++ptr;
    }
    
    return nullptr;
}

} // namespace RawrXD
