#include "ide/IDETheme.hpp"
#include <fstream>
#include <sstream>

namespace Sovereign {
namespace IDE {

IDETheme& IDETheme::Instance() {
    static IDETheme instance;
    return instance;
}

void IDETheme::Initialize() {
    ApplyDarkTheme(); // Default to dark theme
}

void IDETheme::SetTheme(ThemeType type) {
    m_currentTheme = type;
    switch (type) {
        case ThemeType::Dark:
            ApplyDarkTheme();
            break;
        case ThemeType::Light:
            ApplyLightTheme();
            break;
        case ThemeType::Custom:
            // Custom colors already set
            break;
    }
}

void IDETheme::SetCustomTheme(const ThemeColors& colors) {
    m_colors = colors;
    m_currentTheme = ThemeType::Custom;
}

void IDETheme::ApplyToWindow(HWND hwnd) {
    // Set window background
    SetClassLongPtr(hwnd, GCLP_HBRBACKGROUND, (LONG_PTR)CreateSolidBrush(m_colors.background));
    InvalidateRect(hwnd, nullptr, TRUE);
}

void IDETheme::ApplyDarkTheme() {
    m_colors = {
        RGB(13, 17, 23),      // background
        RGB(201, 209, 217),   // foreground
        RGB(88, 166, 255),    // accent
        RGB(63, 185, 80),     // success
        RGB(240, 136, 62),    // warning
        RGB(248, 81, 73),     // error
        RGB(22, 27, 34),      // panelBackground
        RGB(48, 54, 61),      // panelBorder
        RGB(201, 209, 217),   // textPrimary
        RGB(139, 148, 158),   // textSecondary
        RGB(56, 139, 253),    // highlight
        RGB(33, 38, 45)       // selection
    };
}

void IDETheme::ApplyLightTheme() {
    m_colors = {
        RGB(255, 255, 255),   // background
        RGB(36, 41, 47),      // foreground
        RGB(9, 105, 218),     // accent
        RGB(31, 136, 61),     // success
        RGB(154, 103, 0),     // warning
        RGB(207, 34, 46),     // error
        RGB(246, 248, 250),   // panelBackground
        RGB(208, 215, 222),   // panelBorder
        RGB(36, 41, 47),      // textPrimary
        RGB(87, 96, 106),     // textSecondary
        RGB(9, 105, 218),     // highlight
        RGB(221, 244, 255)    // selection
    };
}

bool IDETheme::SaveTheme(const std::wstring& path) {
    std::ofstream file(path, std::ios::out);
    if (!file.is_open()) return false;
    
    file << "# Sovereign IDE Theme\n";
    file << "ThemeType=" << (m_currentTheme == ThemeType::Dark ? "Dark" : 
                            m_currentTheme == ThemeType::Light ? "Light" : "Custom") << "\n";
    file << "Background=" << m_colors.background << "\n";
    file << "Foreground=" << m_colors.foreground << "\n";
    file << "Accent=" << m_colors.accent << "\n";
    file << "Success=" << m_colors.success << "\n";
    file << "Warning=" << m_colors.warning << "\n";
    file << "Error=" << m_colors.error << "\n";
    file << "PanelBackground=" << m_colors.panelBackground << "\n";
    file << "PanelBorder=" << m_colors.panelBorder << "\n";
    file << "TextPrimary=" << m_colors.textPrimary << "\n";
    file << "TextSecondary=" << m_colors.textSecondary << "\n";
    file << "Highlight=" << m_colors.highlight << "\n";
    file << "Selection=" << m_colors.selection << "\n";
    
    file.close();
    return true;
}

bool IDETheme::LoadTheme(const std::wstring& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        if (key == "ThemeType") {
            if (value == "Dark") m_currentTheme = ThemeType::Dark;
            else if (value == "Light") m_currentTheme = ThemeType::Light;
            else m_currentTheme = ThemeType::Custom;
        } else if (key == "Background") {
            m_colors.background = std::stoul(value);
        } else if (key == "Foreground") {
            m_colors.foreground = std::stoul(value);
        } else if (key == "Accent") {
            m_colors.accent = std::stoul(value);
        } else if (key == "Success") {
            m_colors.success = std::stoul(value);
        } else if (key == "Warning") {
            m_colors.warning = std::stoul(value);
        } else if (key == "Error") {
            m_colors.error = std::stoul(value);
        } else if (key == "PanelBackground") {
            m_colors.panelBackground = std::stoul(value);
        } else if (key == "PanelBorder") {
            m_colors.panelBorder = std::stoul(value);
        } else if (key == "TextPrimary") {
            m_colors.textPrimary = std::stoul(value);
        } else if (key == "TextSecondary") {
            m_colors.textSecondary = std::stoul(value);
        } else if (key == "Highlight") {
            m_colors.highlight = std::stoul(value);
        } else if (key == "Selection") {
            m_colors.selection = std::stoul(value);
        }
    }
    
    file.close();
    return true;
}

} // namespace IDE
} // namespace Sovereign
