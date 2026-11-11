// Win32IDE_Themes.cpp — Custom Themes (Batch 4 U01)
// Light, dark, and high-contrast themes.
// IDETheme is defined in Win32IDE.h (single authoritative definition);
// this TU supplies the palette table, default-theme initialization, and
// the apply/save entry points.
#include "Win32IDE.h"
#include <windows.h>
#include <array>
#include <fstream>
#include <sstream>
#include <filesystem>

#include "core/json_util.hpp"

namespace {

struct ThemePalette {
    const char* name;
    COLORREF    background;
    COLORREF    text;
    COLORREF    keyword;
    COLORREF    comment;
    COLORREF    string;
    COLORREF    number;
    COLORREF    oper;
    COLORREF    type;
    COLORREF    preproc;
    COLORREF    func;
    COLORREF    accent;
    COLORREF    selection;
    COLORREF    lineNumber;
};

// Dark+ inspired (default)
constexpr ThemePalette kDark{
    "Dark+",
    RGB(30, 30, 30), RGB(212, 212, 212),
    RGB(86, 156, 214), RGB(106, 153, 85), RGB(206, 145, 120),
    RGB(181, 206, 168), RGB(212, 212, 212),
    RGB(78, 201, 176), RGB(198, 120, 221), RGB(220, 220, 170),
    RGB(0, 122, 204), RGB(38, 79, 120), RGB(120, 120, 120)
};

// Light+
constexpr ThemePalette kLight{
    "Light+",
    RGB(255, 255, 255), RGB(0, 0, 0),
    RGB(0, 0, 255), RGB(0, 128, 0), RGB(163, 21, 21),
    RGB(9, 136, 90), RGB(0, 0, 0),
    RGB(42, 0, 255), RGB(175, 0, 219), RGB(121, 94, 38),
    RGB(0, 122, 204), RGB(173, 214, 255), RGB(150, 150, 150)
};

// High contrast
constexpr ThemePalette kHighContrast{
    "High Contrast",
    RGB(0, 0, 0), RGB(255, 255, 255),
    RGB(255, 255, 0), RGB(128, 255, 128), RGB(255, 160, 160),
    RGB(160, 255, 255), RGB(255, 255, 255),
    RGB(0, 255, 255), RGB(255, 160, 255), RGB(255, 255, 160),
    RGB(255, 215, 0), RGB(0, 120, 215), RGB(180, 180, 180)
};

const ThemePalette& paletteFor(const std::string& name) {
    if (name == "Light+" || name == "light")     return kLight;
    if (name == "High Contrast" || name == "hc") return kHighContrast;
    return kDark;
}

void applyPalette(IDETheme& t, const ThemePalette& p) {
    t.backgroundColor    = p.background;
    t.textColor          = p.text;
    t.keywordColor       = p.keyword;
    t.commentColor       = p.comment;
    t.stringColor        = p.string;
    t.numberColor        = p.number;
    t.operatorColor      = p.oper;
    t.selectionColor     = p.selection;
    t.lineNumberColor    = p.lineNumber;
    t.typeColor          = p.type;
    t.preprocessorColor  = p.preproc;
    t.functionColor      = p.func;
    t.accentColor        = p.accent;
    t.fontName           = t.fontName.empty() ? std::string("Consolas") : t.fontName;
    t.fontSize           = t.fontSize == 0 ? 12 : t.fontSize;
    t.darkMode           = (p.background == RGB(30, 30, 30) || p.background == RGB(0, 0, 0));
}

} // namespace

void Win32IDE::initThemes() {
    // Start from the Dark+ palette, then overlay any stored appearance values.
    applyPalette(m_currentTheme, kDark);
    m_currentTheme.fontName = m_appearance.fontFamily.empty()
                                  ? std::string("Consolas")
                                  : m_appearance.fontFamily;
    m_currentTheme.fontSize = m_appearance.editorFontSizePt > 0
                                  ? m_appearance.editorFontSizePt
                                  : 12;

    // Register the built-in palettes so the theme picker can enumerate them.
    m_themes[kDark.name]         = m_currentTheme;
    m_themes[kLight.name]        = m_currentTheme;
    m_themes[kHighContrast.name] = m_currentTheme;
    applyPalette(m_themes[kLight.name], kLight);
    applyPalette(m_themes[kHighContrast.name], kHighContrast);

    // Restore the user's persisted theme choice if one was recorded.
    if (!m_appearance.themeName.empty()) {
        auto it = m_themes.find(m_appearance.themeName);
        if (it != m_themes.end()) {
            m_currentTheme = it->second;
        } else {
            applyPalette(m_currentTheme, paletteFor(m_appearance.themeName));
        }
    }

    appendToOutput("[Themes] Initialized (Dark+, Light+, High Contrast).\n",
                   "Output", OutputSeverity::Info);
}

void Win32IDE::applyTheme(const std::string& themeName) {
    auto it = m_themes.find(themeName);
    if (it != m_themes.end()) {
        m_currentTheme = it->second;
    } else {
        applyPalette(m_currentTheme, paletteFor(themeName));
        m_themes[themeName] = m_currentTheme;
    }

    // Preserve user font preferences across theme switches.
    if (!m_appearance.fontFamily.empty()) {
        m_currentTheme.fontName = m_appearance.fontFamily;
    }
    if (m_appearance.editorFontSizePt > 0) {
        m_currentTheme.fontSize = m_appearance.editorFontSizePt;
    }

    m_appearance.themeName = themeName;

    // Repaint editor with new colors if it exists.
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, EM_SETBKGNDCOLOR, 0,
                    (LPARAM)m_currentTheme.backgroundColor);
        InvalidateRect(m_hwndEditor, nullptr, TRUE);
    }

    appendToOutput("[Themes] Applied: " + themeName + "\n",
                   "Output", OutputSeverity::Info);
    saveSettings();
}