// theme_engine.cpp — Theme Engine Implementation
#include "theme_engine.hpp"
#include <fstream>
#include <algorithm>
#include <regex>
#include <sstream>

namespace RawrXD {
namespace UX {

Color Color::FromHex(const std::string& hex) {
    Color c;
    std::string h = hex;
    // Remove #
    if (!h.empty() && h[0] == '#') h = h.substr(1);

    auto hexToVal = [](char ch) -> uint8_t {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
        if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
        return 0;
    };

    if (h.length() == 6) {
        c.r = (hexToVal(h[0]) << 4) | hexToVal(h[1]);
        c.g = (hexToVal(h[2]) << 4) | hexToVal(h[3]);
        c.b = (hexToVal(h[4]) << 4) | hexToVal(h[5]);
        c.a = 255;
    } else if (h.length() == 8) {
        c.r = (hexToVal(h[0]) << 4) | hexToVal(h[1]);
        c.g = (hexToVal(h[2]) << 4) | hexToVal(h[3]);
        c.b = (hexToVal(h[4]) << 4) | hexToVal(h[5]);
        c.a = (hexToVal(h[6]) << 4) | hexToVal(h[7]);
    }

    return c;
}

std::string Color::ToHex() const {
    char buf[10];
    snprintf(buf, sizeof(buf), "#%02x%02x%02x", r, g, b);
    return std::string(buf);
}

// ============================================================================
// ThemeEngine
// ============================================================================
ThemeEngine& ThemeEngine::Get() {
    static ThemeEngine instance;
    return instance;
}

void ThemeEngine::RegisterTheme(const ThemeDefinition& theme) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_themes[theme.name] = theme;
}

bool ThemeEngine::SetTheme(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_themes.find(name);
    if (it == m_themes.end()) return false;

    m_activeTheme = name;
    if (m_onThemeChanged) m_onThemeChanged(name);
    return true;
}

const ThemeDefinition* ThemeEngine::GetActiveTheme() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_themes.find(m_activeTheme);
    return it != m_themes.end() ? &it->second : nullptr;
}

const ThemeDefinition* ThemeEngine::GetTheme(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_themes.find(name);
    return it != m_themes.end() ? &it->second : nullptr;
}

std::vector<const ThemeDefinition*> ThemeEngine::ListThemes() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const ThemeDefinition*> result;
    for (const auto& [name, theme] : m_themes) {
        result.push_back(&theme);
    }
    return result;
}

std::vector<const ThemeDefinition*> ThemeEngine::ListThemesByType(const std::string& type) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<const ThemeDefinition*> result;
    for (const auto& [name, theme] : m_themes) {
        if (theme.type == type) result.push_back(&theme);
    }
    return result;
}

Color ThemeEngine::GetColor(const std::string& tokenName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto themeIt = m_themes.find(m_activeTheme);
    if (themeIt == m_themes.end()) return Color(200, 200, 200); // Default light gray

    auto colorIt = themeIt->second.colors.find(tokenName);
    if (colorIt != themeIt->second.colors.end()) {
        return colorIt->second;
    }

    return Color(200, 200, 200);
}

Color ThemeEngine::GetTokenColor(const std::string& scope, const std::string& property) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto themeIt = m_themes.find(m_activeTheme);
    if (themeIt == m_themes.end()) return Color(200, 200, 200);

    // Check token colors
    for (const auto& [tokenScope, colors] : themeIt->second.tokenColors) {
        if (scope.find(tokenScope) == 0 || tokenScope == scope) {
            auto propIt = colors.find(property);
            if (propIt != colors.end()) return propIt->second;
        }
    }

    return GetColor("editor.foreground");
}

bool ThemeEngine::LoadThemeFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return false;

    ThemeDefinition theme;
    theme.name = std::filesystem::path(filePath).stem().string();
    theme.displayName = theme.name;

    std::string line;
    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"name\"") != std::string::npos) theme.displayName = parseStr(line, "name");
        if (line.find("\"type\"") != std::string::npos) theme.type = parseStr(line, "type");
        if (line.find("\"author\"") != std::string::npos) theme.author = parseStr(line, "author");

        // Parse color entries like: "editor.background": "#1e1e1e"
        std::regex colorPattern(R"("([^"]+)":\s*"#([0-9a-fA-F]+)")");
        std::smatch match;
        if (std::regex_search(line, match, colorPattern)) {
            theme.colors[match[1].str()] = Color::FromHex("#" + match[2].str());
        }
    }

    if (!theme.displayName.empty()) {
        RegisterTheme(theme);
        return true;
    }

    return false;
}

size_t ThemeEngine::LoadThemesFromDirectory(const std::string& directory) {
    size_t count = 0;
    if (!std::filesystem::exists(directory)) return 0;

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            if (LoadThemeFile(entry.path().string())) {
                count++;
            }
        }
    }

    return count;
}

void ThemeEngine::RegisterBuiltinThemes() {
    // Dark Theme (Default)
    {
        ThemeDefinition dark;
        dark.name = "dark-default";
        dark.displayName = "Dark Default";
        dark.type = "dark";
        dark.author = "RawrXD";

        dark.colors["editor.background"] = Color(30, 30, 30);
        dark.colors["editor.foreground"] = Color(212, 212, 212);
        dark.colors["editor.lineHighlight"] = Color(40, 40, 40);
        dark.colors["editor.selection"] = Color(60, 80, 120);
        dark.colors["editor.cursor"] = Color(255, 255, 255);
        dark.colors["editor.lineNumber"] = Color(100, 100, 100);
        dark.colors["editor.indentGuide"] = Color(50, 50, 50);
        dark.colors["editor.activeLineNumber"] = Color(200, 200, 200);
        dark.colors["editorWidget.background"] = Color(40, 40, 40);
        dark.colors["editorWidget.border"] = Color(60, 60, 60);
        dark.colors["sideBar.background"] = Color(37, 37, 37);
        dark.colors["sideBar.foreground"] = Color(200, 200, 200);
        dark.colors["sideBar.border"] = Color(50, 50, 50);
        dark.colors["activityBar.background"] = Color(50, 50, 50);
        dark.colors["activityBar.foreground"] = Color(255, 255, 255);
        dark.colors["activityBar.inactiveForeground"] = Color(150, 150, 150);
        dark.colors["titleBar.background"] = Color(30, 30, 30);
        dark.colors["titleBar.foreground"] = Color(200, 200, 200);
        dark.colors["statusBar.background"] = Color(0, 122, 204);
        dark.colors["statusBar.foreground"] = Color(255, 255, 255);
        dark.colors["tab.activeBackground"] = Color(30, 30, 30);
        dark.colors["tab.activeForeground"] = Color(255, 255, 255);
        dark.colors["tab.inactiveBackground"] = Color(45, 45, 45);
        dark.colors["tab.inactiveForeground"] = Color(150, 150, 150);
        dark.colors["tab.border"] = Color(60, 60, 60);
        dark.colors["input.background"] = Color(60, 60, 60);
        dark.colors["input.foreground"] = Color(212, 212, 212);
        dark.colors["input.border"] = Color(80, 80, 80);
        dark.colors["button.background"] = Color(0, 122, 204);
        dark.colors["button.foreground"] = Color(255, 255, 255);
        dark.colors["button.hoverBackground"] = Color(0, 102, 184);
        dark.colors["dropdown.background"] = Color(60, 60, 60);
        dark.colors["dropdown.foreground"] = Color(212, 212, 212);
        dark.colors["dropdown.border"] = Color(80, 80, 80);
        dark.colors["list.activeSelectionBackground"] = Color(0, 122, 204);
        dark.colors["list.activeSelectionForeground"] = Color(255, 255, 255);
        dark.colors["list.hoverBackground"] = Color(50, 50, 50);
        dark.colors["scrollbar.shadow"] = Color(0, 0, 0, 100);
        dark.colors["scrollbar.sliderBackground"] = Color(100, 100, 100, 100);
        dark.colors["scrollbar.sliderHoverBackground"] = Color(150, 150, 150, 100);
        dark.colors["panel.background"] = Color(30, 30, 30);
        dark.colors["panel.border"] = Color(50, 50, 50);
        dark.colors["terminal.background"] = Color(30, 30, 30);
        dark.colors["terminal.foreground"] = Color(212, 212, 212);
        dark.colors["terminal.ansiGreen"] = Color(0, 200, 0);
        dark.colors["terminal.ansiRed"] = Color(200, 0, 0);
        dark.colors["terminal.ansiBlue"] = Color(0, 100, 200);
        dark.colors["terminal.ansiYellow"] = Color(200, 200, 0);
        dark.colors["terminal.ansiCyan"] = Color(0, 200, 200);
        dark.colors["terminal.ansiMagenta"] = Color(200, 0, 200);
        dark.colors["terminal.ansiWhite"] = Color(255, 255, 255);
        dark.colors["terminal.ansiBlack"] = Color(0, 0, 0);
        dark.colors["notification.background"] = Color(50, 50, 50);
        dark.colors["notification.foreground"] = Color(212, 212, 212);
        dark.colors["notification.buttonBackground"] = Color(0, 122, 204);
        dark.colors["notification.buttonForeground"] = Color(255, 255, 255);
        dark.colors["debugToolBar.background"] = Color(50, 50, 50);
        dark.colors["welcomePage.background"] = Color(30, 30, 30);
        dark.colors["welcomePage.foreground"] = Color(212, 212, 212);
        dark.colors["commandPalette.background"] = Color(40, 40, 40);
        dark.colors["commandPalette.foreground"] = Color(212, 212, 212);
        dark.colors["commandPalette.highlight"] = Color(0, 122, 204);

        // Token colors
        dark.tokenColors["comment"] = {{"foreground", Color(106, 153, 85)}};
        dark.tokenColors["keyword"] = {{"foreground", Color(86, 156, 214)}};
        dark.tokenColors["string"] = {{"foreground", Color(206, 145, 120)}};
        dark.tokenColors["number"] = {{"foreground", Color(181, 206, 168)}};
        dark.tokenColors["type"] = {{"foreground", Color(78, 201, 176)}};
        dark.tokenColors["function"] = {{"foreground", Color(220, 220, 170)}};
        dark.tokenColors["variable"] = {{"foreground", Color(156, 220, 254)}};
        dark.tokenColors["constant"] = {{"foreground", Color(79, 193, 255)}};
        dark.tokenColors["operator"] = {{"foreground", Color(180, 180, 180)}};
        dark.tokenColors["preprocessor"] = {{"foreground", Color(190, 150, 200)}};

        RegisterTheme(dark);
    }

    // Light Theme
    {
        ThemeDefinition light;
        light.name = "light-default";
        light.displayName = "Light Default";
        light.type = "light";
        light.author = "RawrXD";

        light.colors["editor.background"] = Color(255, 255, 255);
        light.colors["editor.foreground"] = Color(30, 30, 30);
        light.colors["editor.lineHighlight"] = Color(240, 240, 240);
        light.colors["editor.selection"] = Color(180, 200, 240);
        light.colors["editor.cursor"] = Color(0, 0, 0);
        light.colors["editor.lineNumber"] = Color(150, 150, 150);
        light.colors["editor.indentGuide"] = Color(220, 220, 220);
        light.colors["sideBar.background"] = Color(245, 245, 245);
        light.colors["sideBar.foreground"] = Color(50, 50, 50);
        light.colors["activityBar.background"] = Color(50, 50, 50);
        light.colors["activityBar.foreground"] = Color(255, 255, 255);
        light.colors["statusBar.background"] = Color(0, 122, 204);
        light.colors["statusBar.foreground"] = Color(255, 255, 255);
        light.colors["tab.activeBackground"] = Color(255, 255, 255);
        light.colors["tab.activeForeground"] = Color(30, 30, 30);
        light.colors["tab.inactiveBackground"] = Color(235, 235, 235);
        light.colors["tab.inactiveForeground"] = Color(100, 100, 100);
        light.colors["input.background"] = Color(255, 255, 255);
        light.colors["input.foreground"] = Color(30, 30, 30);
        light.colors["input.border"] = Color(200, 200, 200);
        light.colors["button.background"] = Color(0, 122, 204);
        light.colors["button.foreground"] = Color(255, 255, 255);
        light.colors["terminal.background"] = Color(255, 255, 255);
        light.colors["terminal.foreground"] = Color(30, 30, 30);

        RegisterTheme(light);
    }

    // High Contrast Theme
    {
        ThemeDefinition hc;
        hc.name = "high-contrast";
        hc.displayName = "High Contrast";
        hc.type = "highContrast";
        hc.author = "RawrXD";

        hc.colors["editor.background"] = Color(0, 0, 0);
        hc.colors["editor.foreground"] = Color(255, 255, 255);
        hc.colors["editor.selection"] = Color(100, 100, 100);
        hc.colors["editor.cursor"] = Color(255, 255, 255);
        hc.colors["editor.lineNumber"] = Color(150, 150, 150);
        hc.colors["sideBar.background"] = Color(0, 0, 0);
        hc.colors["sideBar.foreground"] = Color(255, 255, 255);
        hc.colors["sideBar.border"] = Color(255, 255, 255);
        hc.colors["activityBar.background"] = Color(0, 0, 0);
        hc.colors["activityBar.foreground"] = Color(255, 255, 255);
        hc.colors["statusBar.background"] = Color(0, 0, 0);
        hc.colors["statusBar.foreground"] = Color(255, 255, 255);
        hc.colors["statusBar.border"] = Color(255, 255, 255);
        hc.colors["tab.activeBackground"] = Color(0, 0, 0);
        hc.colors["tab.activeForeground"] = Color(255, 255, 255);
        hc.colors["tab.border"] = Color(255, 255, 255);
        hc.colors["input.background"] = Color(0, 0, 0);
        hc.colors["input.foreground"] = Color(255, 255, 255);
        hc.colors["input.border"] = Color(255, 255, 255);
        hc.colors["button.background"] = Color(0, 0, 0);
        hc.colors["button.foreground"] = Color(255, 255, 255);
        hc.colors["button.border"] = Color(255, 255, 255);

        RegisterTheme(hc);
    }

    // Set default theme
    m_activeTheme = "dark-default";
}

} // namespace UX
} // namespace RawrXD
