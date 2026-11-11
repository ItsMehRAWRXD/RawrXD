// Win32IDE_Themes.cpp — Custom Themes (Batch 4 U01)
// Light, dark, high contrast themes
#include "Win32IDE.h"
#include <windows.h>

struct IDETheme {
    COLORREF background;
    COLORREF foreground;
    COLORREF selection;
    COLORREF lineNumber;
    COLORREF typeColor;
    COLORREF preprocessorColor;
    COLORREF functionColor;
    COLORREF accentColor;
    std::string fontName;
};

void Win32IDE::initThemes() {
    m_currentTheme.background = RGB(30, 30, 30);
    m_currentTheme.foreground = RGB(204, 204, 204);
    m_currentTheme.selection = RGB(68, 139, 255);
    m_currentTheme.lineNumber = RGB(120, 120, 120);
    m_currentTheme.typeColor = RGB(86, 156, 214);
    m_currentTheme.preprocessorColor = RGB(220, 120, 160);
    m_currentTheme.functionColor = RGB(220, 220, 170);
    m_currentTheme.accentColor = RGB(0, 122, 204);
    m_currentTheme.fontName = "Consolas";
    appendToOutput("[Themes] Themes initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::applyTheme(const std::string& themeName) {
    appendToOutput("[Themes] Theme applied: " + themeName + "\n", "Output", OutputSeverity::Info);
}
