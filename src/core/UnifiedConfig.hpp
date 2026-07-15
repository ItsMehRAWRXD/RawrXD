#pragma once
#include <string_view>
#include <cstdint>
#include <cstddef>

namespace RawrXD {

// Configuration value types
enum class ConfigValueType : uint8_t {
    Null = 0,
    Boolean,
    Integer,
    Float,
    String,
    Array,
    Object
};

// Configuration value (non-owning view)
struct ConfigValue {
    ConfigValueType type;
    union {
        bool boolValue;
        int64_t intValue;
        double floatValue;
    };
    std::string_view stringValue; // For string/array/object (points into mapped file)
    
    // Convenience accessors
    bool AsBool() const noexcept { return type == ConfigValueType::Boolean ? boolValue : false; }
    int64_t AsInt() const noexcept { return type == ConfigValueType::Integer ? intValue : 0; }
    double AsFloat() const noexcept { return type == ConfigValueType::Float ? floatValue : 0.0; }
    std::string_view AsString() const noexcept { return type == ConfigValueType::String ? stringValue : std::string_view{}; }
    
    bool IsNull() const noexcept { return type == ConfigValueType::Null; }
    bool IsBool() const noexcept { return type == ConfigValueType::Boolean; }
    bool IsInt() const noexcept { return type == ConfigValueType::Integer; }
    bool IsFloat() const noexcept { return type == ConfigValueType::Float; }
    bool IsString() const noexcept { return type == ConfigValueType::String; }
};

// Single-pass non-allocating JSON5 scanner
// Uses pointer views into memory-mapped file (zero heap allocations)
class UnifiedConfig {
public:
    UnifiedConfig() noexcept;
    ~UnifiedConfig();

    // Disable copy/move
    UnifiedConfig(const UnifiedConfig&) = delete;
    UnifiedConfig& operator=(const UnifiedConfig&) = delete;
    UnifiedConfig(UnifiedConfig&&) = delete;
    UnifiedConfig& operator=(UnifiedConfig&&) = delete;

    // Load configuration from file (memory-mapped)
    bool LoadFromFile(const wchar_t* filePath) noexcept;
    
    // Load configuration from string view (no allocation)
    bool LoadFromString(std::string_view json) noexcept;
    
    // Reload configuration (atomic swap)
    bool Reload() noexcept;
    
    // Unload and cleanup
    void Unload() noexcept;

    // --- Value Access ---
    
    // Get value by key path (e.g., "model/path" or "ui/theme")
    ConfigValue Get(std::string_view keyPath) const noexcept;
    
    // Get with default value
    bool GetBool(std::string_view keyPath, bool defaultValue = false) const noexcept;
    int64_t GetInt(std::string_view keyPath, int64_t defaultValue = 0) const noexcept;
    double GetFloat(std::string_view keyPath, double defaultValue = 0.0) const noexcept;
    std::string_view GetString(std::string_view keyPath, std::string_view defaultValue = {}) const noexcept;

    // Check if key exists
    bool HasKey(std::string_view keyPath) const noexcept;
    
    // Get all keys at path (for iteration)
    // Returns count, fills provided array (maxCount items)
    size_t GetKeys(std::string_view path, std::string_view* outKeys, size_t maxCount) const noexcept;

    // --- Schema Validation ---
    
    // Validate against schema (returns true if valid)
    bool Validate() const noexcept;
    
    // Get last error message
    std::string_view GetLastError() const noexcept { return m_lastError; }

    // Check if loaded
    bool IsLoaded() const noexcept { return m_data != nullptr; }
    
    // Get raw data view
    std::string_view GetRawData() const noexcept;

private:
    // Memory-mapped file handle
    void* m_hFile;
    void* m_hMapping;
    const char* m_data;
    size_t m_dataSize;
    
    // Error state
    mutable std::string_view m_lastError;
    
    // Internal parsing
    const char* ParseValue(const char* ptr, const char* end, ConfigValue& outValue) const noexcept;
    const char* ParseString(const char* ptr, const char* end, std::string_view& outString) const noexcept;
    const char* ParseNumber(const char* ptr, const char* end, ConfigValue& outValue) const noexcept;
    const char* SkipWhitespace(const char* ptr, const char* end) const noexcept;
    const char* FindKey(const char* ptr, const char* end, std::string_view key) const noexcept;
};

// Global config accessor
UnifiedConfig* GetGlobalConfig() noexcept;
void SetGlobalConfig(UnifiedConfig* config) noexcept;

// Predefined config keys (compile-time constants)
namespace ConfigKeys {
    constexpr std::string_view ModelPath = "model/path";
    constexpr std::string_view ModelContextSize = "model/context_size";
    constexpr std::string_view ModelGpuLayers = "model/gpu_layers";
    constexpr std::string_view UiTheme = "ui/theme";
    constexpr std::string_view UiFontSize = "ui/font_size";
    constexpr std::string_view UiFontFamily = "ui/font_family";
    constexpr std::string_view KeybindingsSave = "keybindings/save";
    constexpr std::string_view KeybindingsOpen = "keybindings/open";
    constexpr std::string_view LspEnabled = "lsp/enabled";
    constexpr std::string_view LspTimeout = "lsp/timeout_ms";
}

} // namespace RawrXD
