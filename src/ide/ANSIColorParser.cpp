/**
 * @file ANSIColorParser.cpp
 * @brief ANSI SGR Parser Implementation
 */

#include "ANSIColorParser.hpp"
#include <richedit.h>
#include <sstream>
#include <regex>
#include <algorithm>

namespace RawrXD::IDE {

// Standard Windows console colors
const COLORREF ANSIColorParser::s_standardColors[16] = {
    RGB(0, 0, 0),       // Black (0)
    RGB(128, 0, 0),     // Dark Red (1)
    RGB(0, 128, 0),     // Dark Green (2)
    RGB(128, 128, 0),   // Dark Yellow (3)
    RGB(0, 0, 128),     // Dark Blue (4)
    RGB(128, 0, 128),   // Dark Magenta (5)
    RGB(0, 128, 128),   // Dark Cyan (6)
    RGB(192, 192, 192), // Light Gray (7)
    RGB(128, 128, 128), // Dark Gray (8)
    RGB(255, 0, 0),     // Red (9)
    RGB(0, 255, 0),     // Green (10)
    RGB(255, 255, 0),   // Yellow (11)
    RGB(0, 0, 255),     // Blue (12)
    RGB(255, 0, 255),   // Magenta (13)
    RGB(0, 255, 255),   // Cyan (14)
    RGB(255, 255, 255)  // White (15)
};

// Bright variants (for 90-97, 100-107)
const COLORREF ANSIColorParser::s_brightColors[16] = {
    RGB(128, 128, 128), // Bright Black (Gray)
    RGB(255, 0, 0),     // Bright Red
    RGB(0, 255, 0),     // Bright Green
    RGB(255, 255, 0),   // Bright Yellow
    RGB(0, 128, 255),   // Bright Blue
    RGB(255, 0, 255),   // Bright Magenta
    RGB(0, 255, 255),   // Bright Cyan
    RGB(255, 255, 255), // Bright White
    RGB(128, 128, 128), // Duplicate for safety
    RGB(255, 0, 0),
    RGB(0, 255, 0),
    RGB(255, 255, 0),
    RGB(0, 128, 255),
    RGB(255, 0, 255),
    RGB(0, 255, 255),
    RGB(255, 255, 255)
};

COLORREF ANSIColorParser::s_256Colors[256];
bool ANSIColorParser::s_256ColorsInitialized = false;

void ANSIColorParser::Init256Colors() {
    if (s_256ColorsInitialized) return;
    
    // First 16 colors: standard + bright
    for (int i = 0; i < 16; i++) {
        s_256Colors[i] = s_standardColors[i];
    }
    
    // 16-231: 6x6x6 color cube
    for (int r = 0; r < 6; r++) {
        for (int g = 0; g < 6; g++) {
            for (int b = 0; b < 6; b++) {
                int index = 16 + (r * 36) + (g * 6) + b;
                s_256Colors[index] = RGB(
                    r == 0 ? 0 : (r * 40 + 55),
                    g == 0 ? 0 : (g * 40 + 55),
                    b == 0 ? 0 : (b * 40 + 55)
                );
            }
        }
    }
    
    // 232-255: Grayscale ramp
    for (int i = 0; i < 24; i++) {
        int gray = 8 + (i * 10);
        s_256Colors[232 + i] = RGB(gray, gray, gray);
    }
    
    s_256ColorsInitialized = true;
}

void ANSIColorAttributes::Reset() {
    fgR = fgG = fgB = 255;  // White
    bgR = bgG = bgB = 0;    // Black
    bold = faint = italic = underline = blink = reverse = conceal = strikethrough = false;
    isDefault = true;
}

COLORREF ANSIColorAttributes::GetForegroundColor() const {
    if (reverse) {
        return RGB(bgR, bgG, bgB);
    }
    return RGB(fgR, fgG, fgB);
}

COLORREF ANSIColorAttributes::GetBackgroundColor() const {
    if (reverse) {
        return RGB(fgR, fgG, fgB);
    }
    return RGB(bgR, bgG, bgB);
}

ANSIColorParser::ANSIColorParser() {
    Init256Colors();
    m_currentAttrs.Reset();
}

ANSIColorParser::~ANSIColorParser() = default;

std::vector<ColoredTextSegment> ANSIColorParser::Parse(const std::string& text) {
    // Convert to wide and parse
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    std::wstring wtext(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wtext[0], len);
    return Parse(wtext);
}

std::vector<ColoredTextSegment> ANSIColorParser::Parse(const std::wstring& text) {
    std::vector<ColoredTextSegment> segments;
    
    if (!m_enabled) {
        // No parsing, return single segment
        segments.push_back({text, m_currentAttrs, 0});
        return segments;
    }
    
    std::wstring currentText;
    size_t i = 0;
    size_t lastSegmentStart = 0;
    
    while (i < text.length()) {
        // Check for escape sequence
        if (text[i] == L'\x1B' && i + 1 < text.length() && text[i + 1] == L'[') {
            // Save current segment before processing escape
            if (!currentText.empty()) {
                segments.push_back({currentText, m_currentAttrs, lastSegmentStart});
                currentText.clear();
            }
            
            // Parse CSI sequence
            i += 2;  // Skip ESC[
            std::vector<int> params;
            std::wstring paramStr;
            
            // Collect parameters
            while (i < text.length() && text[i] >= L'0' && text[i] <= L'?') {
                if (text[i] == L';') {
                    if (!paramStr.empty()) {
                        params.push_back(_wtoi(paramStr.c_str()));
                        paramStr.clear();
                    }
                } else {
                    paramStr += text[i];
                }
                i++;
            }
            
            // Final parameter
            if (!paramStr.empty()) {
                params.push_back(_wtoi(paramStr.c_str()));
            }
            
            // Get command character
            if (i < text.length()) {
                wchar_t cmd = text[i];
                if (cmd == L'm') {
                    // SGR command
                    ParseSGRParameters(params);
                }
                // Other CSI commands (cursor movement, etc.) - skip
                i++;
            }
            
            lastSegmentStart = i;
        } else {
            currentText += text[i];
            i++;
        }
    }
    
    // Add final segment
    if (!currentText.empty()) {
        segments.push_back({currentText, m_currentAttrs, lastSegmentStart});
    }
    
    return segments;
}

void ANSIColorParser::ParseSGRParameters(const std::vector<int>& params) {
    if (params.empty()) {
        // ESC[m is same as ESC[0m - reset
        m_currentAttrs.Reset();
        return;
    }
    
    for (size_t i = 0; i < params.size(); i++) {
        int code = params[i];
        
        switch (code) {
            case 0:  // Reset
                m_currentAttrs.Reset();
                break;
            case 1:  // Bold
                m_currentAttrs.bold = true;
                break;
            case 2:  // Faint
                m_currentAttrs.faint = true;
                break;
            case 3:  // Italic
                m_currentAttrs.italic = true;
                break;
            case 4:  // Underline
                m_currentAttrs.underline = true;
                break;
            case 5:  // Blink (slow)
            case 6:  // Blink (rapid)
                m_currentAttrs.blink = true;
                break;
            case 7:  // Reverse video
                m_currentAttrs.reverse = true;
                break;
            case 8:  // Conceal
                m_currentAttrs.conceal = true;
                break;
            case 9:  // Strikethrough
                m_currentAttrs.strikethrough = true;
                break;
            case 22: // Normal intensity (not bold/faint)
                m_currentAttrs.bold = false;
                m_currentAttrs.faint = false;
                break;
            case 23: // Not italic
                m_currentAttrs.italic = false;
                break;
            case 24: // Not underlined
                m_currentAttrs.underline = false;
                break;
            case 25: // Not blinking
                m_currentAttrs.blink = false;
                break;
            case 27: // Not reversed
                m_currentAttrs.reverse = false;
                break;
            case 28: // Reveal
                m_currentAttrs.conceal = false;
                break;
            case 29: // Not strikethrough
                m_currentAttrs.strikethrough = false;
                break;
            case 39: // Default foreground
                m_currentAttrs.fgR = m_currentAttrs.fgG = m_currentAttrs.fgB = 255;
                break;
            case 49: // Default background
                m_currentAttrs.bgR = m_currentAttrs.bgG = m_currentAttrs.bgB = 0;
                break;
            default:
                if (code >= 30 && code <= 37) {
                    // Standard foreground colors
                    COLORREF c = s_standardColors[code - 30];
                    m_currentAttrs.fgR = GetRValue(c);
                    m_currentAttrs.fgG = GetGValue(c);
                    m_currentAttrs.fgB = GetBValue(c);
                } else if (code >= 40 && code <= 47) {
                    // Standard background colors
                    COLORREF c = s_standardColors[code - 40];
                    m_currentAttrs.bgR = GetRValue(c);
                    m_currentAttrs.bgG = GetGValue(c);
                    m_currentAttrs.bgB = GetBValue(c);
                } else if (code >= 90 && code <= 97) {
                    // Bright foreground colors
                    COLORREF c = s_brightColors[code - 90];
                    m_currentAttrs.fgR = GetRValue(c);
                    m_currentAttrs.fgG = GetGValue(c);
                    m_currentAttrs.fgB = GetBValue(c);
                } else if (code >= 100 && code <= 107) {
                    // Bright background colors
                    COLORREF c = s_brightColors[code - 100];
                    m_currentAttrs.bgR = GetRValue(c);
                    m_currentAttrs.bgG = GetGValue(c);
                    m_currentAttrs.bgB = GetBValue(c);
                } else if (code == 38 && i + 1 < params.size()) {
                    // Extended foreground color
                    if (params[i + 1] == 5 && i + 2 < params.size()) {
                        // 256-color palette
                        COLORREF c = Get256Color(params[i + 2]);
                        m_currentAttrs.fgR = GetRValue(c);
                        m_currentAttrs.fgG = GetGValue(c);
                        m_currentAttrs.fgB = GetBValue(c);
                        i += 2;
                    } else if (params[i + 1] == 2 && i + 4 < params.size()) {
                        // True color RGB
                        COLORREF c = GetTrueColor(params[i + 2], params[i + 3], params[i + 4]);
                        m_currentAttrs.fgR = GetRValue(c);
                        m_currentAttrs.fgG = GetGValue(c);
                        m_currentAttrs.fgB = GetBValue(c);
                        i += 4;
                    }
                } else if (code == 48 && i + 1 < params.size()) {
                    // Extended background color
                    if (params[i + 1] == 5 && i + 2 < params.size()) {
                        // 256-color palette
                        COLORREF c = Get256Color(params[i + 2]);
                        m_currentAttrs.bgR = GetRValue(c);
                        m_currentAttrs.bgG = GetGValue(c);
                        m_currentAttrs.bgB = GetBValue(c);
                        i += 2;
                    } else if (params[i + 1] == 2 && i + 4 < params.size()) {
                        // True color RGB
                        COLORREF c = GetTrueColor(params[i + 2], params[i + 3], params[i + 4]);
                        m_currentAttrs.bgR = GetRValue(c);
                        m_currentAttrs.bgG = GetGValue(c);
                        m_currentAttrs.bgB = GetBValue(c);
                        i += 4;
                    }
                }
                break;
        }
    }
    
    m_currentAttrs.isDefault = false;
}

COLORREF ANSIColorParser::Get256Color(int index) const {
    if (index >= 0 && index < 256) {
        return s_256Colors[index];
    }
    return RGB(255, 255, 255);  // Default white
}

COLORREF ANSIColorParser::GetTrueColor(int r, int g, int b) const {
    return RGB(
        static_cast<BYTE>(std::max(0, std::min(255, r))),
        static_cast<BYTE>(std::max(0, std::min(255, g))),
        static_cast<BYTE>(std::max(0, std::min(255, b)))
    );
}

std::string ANSIColorParser::StripANSI(const std::string& text) {
    // Regex to match ANSI escape sequences
    std::regex ansiRegex("\x1B\\[[0-?]*[ -/]*[@-~]");
    return std::regex_replace(text, ansiRegex, "");
}

std::wstring ANSIColorParser::StripANSI(const std::wstring& text) {
    // Wide regex for ANSI sequences
    std::wregex ansiRegex(L"\x1B\\[[0-?]*[ -/]*[@-~]");
    return std::regex_replace(text, ansiRegex, std::wstring());
}

bool ANSIColorParser::ContainsANSI(const std::string& text) {
    return text.find("\x1B[") != std::string::npos;
}

bool ANSIColorParser::ContainsANSI(const std::wstring& text) {
    return text.find(L"\x1B[") != std::wstring::npos;
}

// ============================================================================
// RichEditANSIColorizer Implementation
// ============================================================================

RichEditANSIColorizer::RichEditANSIColorizer() : m_hwnd(nullptr) {}

RichEditANSIColorizer::~RichEditANSIColorizer() {
    Detach();
}

void RichEditANSIColorizer::Attach(HWND hwndRichEdit) {
    m_hwnd = hwndRichEdit;
}

void RichEditANSIColorizer::Detach() {
    m_hwnd = nullptr;
}

void RichEditANSIColorizer::AppendText(const std::string& text) {
    if (!m_hwnd) return;
    
    // Convert to wide
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    std::wstring wtext(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wtext[0], len);
    
    AppendText(wtext);
}

void RichEditANSIColorizer::AppendText(const std::wstring& text) {
    if (!m_hwnd) return;
    
    if (!m_ansiEnabled || !ANSIColorParser::ContainsANSI(text)) {
        // Plain text append
        CHARRANGE cr;
        cr.cpMin = -1;
        cr.cpMax = -1;
        SendMessage(m_hwnd, EM_EXSETSEL, 0, (LPARAM)&cr);
        SendMessage(m_hwnd, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
        return;
    }
    
    // Parse and apply colors
    auto segments = m_parser.Parse(text);
    
    for (const auto& segment : segments) {
        ApplySegment(segment);
    }
}

void RichEditANSIColorizer::ApplySegment(const ColoredTextSegment& segment) {
    if (!m_hwnd || segment.text.empty()) return;
    
    // Get current selection (end of text)
    CHARRANGE cr;
    SendMessage(m_hwnd, EM_EXGETSEL, 0, (LPARAM)&cr);
    long insertPos = cr.cpMax;
    
    // Insert text
    cr.cpMin = -1;
    cr.cpMax = -1;
    SendMessage(m_hwnd, EM_EXSETSEL, 0, (LPARAM)&cr);
    SendMessage(m_hwnd, EM_REPLACESEL, FALSE, (LPARAM)segment.text.c_str());
    
    // Calculate range for formatting
    long newEnd = insertPos + static_cast<long>(segment.text.length());
    CHARRANGE formatRange;
    formatRange.cpMin = insertPos;
    formatRange.cpMax = newEnd;
    
    // Apply formatting
    SetCharFormat(segment.attrs, formatRange);
}

void RichEditANSIColorizer::SetCharFormat(const ANSIColorAttributes& attrs, CHARRANGE& range) {
    CHARFORMAT2W cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR | CFM_BACKCOLOR;
    
    // Set colors
    cf.crTextColor = attrs.GetForegroundColor();
    cf.crBackColor = attrs.GetBackgroundColor();
    
    // Set effects
    if (attrs.bold) {
        cf.dwMask |= CFM_BOLD;
        cf.dwEffects |= CFE_BOLD;
    }
    if (attrs.italic) {
        cf.dwMask |= CFM_ITALIC;
        cf.dwEffects |= CFE_ITALIC;
    }
    if (attrs.underline) {
        cf.dwMask |= CFM_UNDERLINE;
        cf.dwEffects |= CFE_UNDERLINE;
    }
    if (attrs.strikethrough) {
        cf.dwMask |= CFM_STRIKEOUT;
        cf.dwEffects |= CFE_STRIKEOUT;
    }
    
    // Apply to range
    SendMessage(m_hwnd, EM_EXSETSEL, 0, (LPARAM)&range);
    SendMessage(m_hwnd, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

void RichEditANSIColorizer::Clear() {
    if (!m_hwnd) return;
    SetWindowText(m_hwnd, L"");
}

void RichEditANSIColorizer::SetANSIParsingEnabled(bool enabled) {
    m_ansiEnabled = enabled;
}

std::wstring RichEditANSIColorizer::GetPlainText() const {
    if (!m_hwnd) return L"";
    
    // Get text length
    LRESULT len = SendMessage(m_hwnd, WM_GETTEXTLENGTH, 0, 0);
    std::wstring text(len + 1, 0);
    SendMessage(m_hwnd, WM_GETTEXT, len + 1, (LPARAM)text.c_str());
    
    return text;
}

void RichEditANSIColorizer::ScrollToEnd() {
    if (!m_hwnd) return;
    SendMessage(m_hwnd, WM_VSCROLL, SB_BOTTOM, 0);
}

} // namespace RawrXD::IDE
