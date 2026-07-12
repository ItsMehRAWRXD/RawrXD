#pragma once
#include <windows.h>
#include <string>

namespace Sovereign {
namespace IDE {

/**
 * @brief Theme colors
 */
struct ThemeColors {
    COLORREF background;
    COLORREF foreground;
    COLORREF accent;
    COLORREF success;
    COLORREF warning;
    COLORREF error;
    COLORREF panelBackground;
    COLORREF panelBorder;
    COLORREF textPrimary;
    COLORREF textSecondary;
    COLORREF highlight;
    COLORREF selection;
};

/**
 * @brief IDE Theme System (Dark/Light/Custom)
 */
class IDETheme {
public:
    enum class ThemeType {
        Dark,
        Light,
        Custom
    };

    static IDETheme& Instance();

    void Initialize();
    void SetTheme(ThemeType type);
    void SetCustomTheme(const ThemeColors& colors);
    
    ThemeType GetCurrentTheme() const { return m_currentTheme; }
    const ThemeColors& GetColors() const { return m_colors; }
    
    // Apply theme to window
    void ApplyToWindow(HWND hwnd);
    
    // Color accessors
    COLORREF Background() const { return m_colors.background; }
    COLORREF Foreground() const { return m_colors.foreground; }
    COLORREF Accent() const { return m_colors.accent; }
    COLORREF Success() const { return m_colors.success; }
    COLORREF Warning() const { return m_colors.warning; }
    COLORREF Error() const { return m_colors.error; }
    COLORREF PanelBackground() const { return m_colors.panelBackground; }
    COLORREF PanelBorder() const { return m_colors.panelBorder; }
    COLORREF TextPrimary() const { return m_colors.textPrimary; }
    COLORREF TextSecondary() const { return m_colors.textSecondary; }
    COLORREF Highlight() const { return m_colors.highlight; }
    COLORREF Selection() const { return m_colors.selection; }
    
    // Save/Load custom themes
    bool SaveTheme(const std::wstring& path);
    bool LoadTheme(const std::wstring& path);

private:
    IDETheme() = default;
    
    ThemeType m_currentTheme = ThemeType::Dark;
    ThemeColors m_colors;
    
    void ApplyDarkTheme();
    void ApplyLightTheme();
};

} // namespace IDE
} // namespace Sovereign
