// theme_engine.hpp — Theme Engine
#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <cstdint>

namespace RawrXD {
namespace UX {

// ============================================================================
// Color (ARGB)
// ============================================================================
struct Color {
    uint8_t a = 255;
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;

    Color() = default;
    Color(uint8_t r, uint8_t g, uint8_t b, uint8_t a = 255) : a(a), r(r), g(g), b(b) {}

    static Color FromHex(const std::string& hex);
    std::string ToHex() const;

    uint32_t ToARGB() const { return (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(r) << 16) | (static_cast<uint32_t>(g) << 8) | b; }
};

// ============================================================================
// Theme Token
// ============================================================================
struct ThemeToken {
    std::string name;       // "editor.background", "editor.foreground", etc.
    Color color;
    std::string description;
};

// ============================================================================
// Theme Definition
// ============================================================================
struct ThemeDefinition {
    std::string name;
    std::string displayName;
    std::string type;       // "dark", "light", "highContrast"
    std::string author;
    std::string version;
    std::map<std::string, Color> colors;
    std::map<std::string, std::map<std::string, Color>> tokenColors; // scope -> { foreground, background, fontStyle }
};

// ============================================================================
// Theme Engine
// ============================================================================
class ThemeEngine {
public:
    static ThemeEngine& Get();

    // Register a theme
    void RegisterTheme(const ThemeDefinition& theme);

    // Set active theme
    bool SetTheme(const std::string& name);

    // Get active theme
    const ThemeDefinition* GetActiveTheme() const;

    // Get theme by name
    const ThemeDefinition* GetTheme(const std::string& name) const;

    // List all themes
    std::vector<const ThemeDefinition*> ListThemes() const;

    // List themes by type
    std::vector<const ThemeDefinition*> ListThemesByType(const std::string& type) const;

    // Get a color value (resolved from active theme)
    Color GetColor(const std::string& tokenName) const;

    // Get token color for a scope
    Color GetTokenColor(const std::string& scope, const std::string& property = "foreground") const;

    // Load theme from JSON file
    bool LoadThemeFile(const std::string& filePath);

    // Load all themes from a directory
    size_t LoadThemesFromDirectory(const std::string& directory);

    // Built-in themes
    void RegisterBuiltinThemes();

    // Events
    using ThemeChangeCallback = std::function<void(const std::string& themeName)>;
    void OnThemeChanged(ThemeChangeCallback callback) { m_onThemeChanged = callback; }

private:
    ThemeEngine() = default;

    std::map<std::string, ThemeDefinition> m_themes;
    std::string m_activeTheme;
    ThemeChangeCallback m_onThemeChanged;
    mutable std::mutex m_mutex;
};

} // namespace UX
} // namespace RawrXD
