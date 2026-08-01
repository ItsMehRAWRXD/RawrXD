/**
 * @file ANSIColorParser.hpp
 * @brief ANSI SGR Sequence Parser for RichEdit Colorization
 * @status PRODUCTION - Full SGR support for build output
 */

#pragma once

#include <windows.h>
#include <richedit.h>
#include <string>
#include <vector>
#include <cstdint>

namespace RawrXD::IDE {

/**
 * @brief ANSI color attributes parsed from SGR sequences
 */
struct ANSIColorAttributes {
    // Foreground color (RGB)
    uint8_t fgR = 255, fgG = 255, fgB = 255;  // Default: white
    // Background color (RGB)
    uint8_t bgR = 0, bgG = 0, bgB = 0;        // Default: black
    
    // Style flags
    bool bold = false;
    bool faint = false;
    bool italic = false;
    bool underline = false;
    bool blink = false;
    bool reverse = false;
    bool conceal = false;
    bool strikethrough = false;
    
    // State
    bool isDefault = true;
    
    void Reset();
    COLORREF GetForegroundColor() const;
    COLORREF GetBackgroundColor() const;
};

/**
 * @brief Text segment with associated color attributes
 */
struct ColoredTextSegment {
    std::wstring text;
    ANSIColorAttributes attrs;
    size_t startPos;  // Original position in unprocessed text
};

/**
 * @brief ANSI SGR Parser for build output colorization
 * 
 * Supports:
 * - Standard 8 colors (30-37, 40-47)
 * - Bright colors (90-97, 100-107)
 * - 256-color palette (38;5;n, 48;5;n)
 * - True color RGB (38;2;r;g;b, 48;2;r;g;b)
 * - Text styles (bold, italic, underline, etc.)
 * - Reset codes (0, 39, 49, etc.)
 */
class ANSIColorParser {
public:
    ANSIColorParser();
    ~ANSIColorParser();
    
    /**
     * @brief Parse ANSI text and extract colored segments
     * @param text Text potentially containing ANSI escape sequences
     * @return Vector of colored segments
     */
    std::vector<ColoredTextSegment> Parse(const std::string& text);
    std::vector<ColoredTextSegment> Parse(const std::wstring& text);
    
    /**
     * @brief Strip ANSI sequences from text (for plain text output)
     * @param text Text with ANSI sequences
     * @return Plain text without sequences
     */
    static std::string StripANSI(const std::string& text);
    static std::wstring StripANSI(const std::wstring& text);
    
    /**
     * @brief Check if text contains ANSI sequences
     */
    static bool ContainsANSI(const std::string& text);
    static bool ContainsANSI(const std::wstring& text);
    
    /**
     * @brief Enable/disable parsing (for performance when not needed)
     */
    void SetEnabled(bool enabled) { m_enabled = enabled; }
    bool IsEnabled() const { return m_enabled; }

private:
    bool m_enabled = true;
    ANSIColorAttributes m_currentAttrs;
    
    // Standard 16-color palette (Windows console colors)
    static const COLORREF s_standardColors[16];
    static const COLORREF s_brightColors[16];
    
    // 256-color lookup table (XTerm palette)
    static COLORREF s_256Colors[256];
    static bool s_256ColorsInitialized;
    static void Init256Colors();
    
    // Parse SGR parameters
    void ParseSGRParameters(const std::vector<int>& params);
    
    // Color lookup helpers
    COLORREF GetStandardColor(int code, bool foreground) const;
    COLORREF Get256Color(int index) const;
    COLORREF GetTrueColor(int r, int g, int b) const;
};

/**
 * @brief RichEdit colorizer using parsed ANSI attributes
 */
class RichEditANSIColorizer {
public:
    RichEditANSIColorizer();
    ~RichEditANSIColorizer();
    
    /**
     * @brief Attach to a RichEdit control
     */
    void Attach(HWND hwndRichEdit);
    void Detach();
    
    /**
     * @brief Append text with ANSI color support
     */
    void AppendText(const std::string& text);
    void AppendText(const std::wstring& text);
    
    /**
     * @brief Clear the control
     */
    void Clear();
    
    /**
     * @brief Set whether to enable ANSI parsing
     */
    void SetANSIParsingEnabled(bool enabled);
    
    /**
     * @brief Get plain text content (strips ANSI)
     */
    std::wstring GetPlainText() const;
    
    /**
     * @brief Scroll to end
     */
    void ScrollToEnd();

private:
    HWND m_hwnd;
    ANSIColorParser m_parser;
    bool m_ansiEnabled = true;
    
    void ApplySegment(const ColoredTextSegment& segment);
    void SetCharFormat(const ANSIColorAttributes& attrs, CHARRANGE& range);
};

} // namespace RawrXD::IDE
