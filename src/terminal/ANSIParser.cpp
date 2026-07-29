// ============================================================================
// ANSIParser.cpp - Production ANSI Escape Sequence Parser Implementation
// ============================================================================

#include "ANSIParser.hpp"
#include <cctype>
#include <sstream>
#include <algorithm>

namespace rawrxd::terminal {

// ============================================================================
// Color Implementation
// ============================================================================
Color Color::From8Bit(uint8_t index) {
    // Standard 8-bit ANSI colors
    if (index < 16) {
        // Standard colors (0-7) and bright colors (8-15)
        static const uint8_t standardColors[16][3] = {
            {0, 0, 0},        // Black
            {128, 0, 0},      // Red
            {0, 128, 0},      // Green
            {128, 128, 0},    // Yellow
            {0, 0, 128},      // Blue
            {128, 0, 128},    // Magenta
            {0, 128, 128},    // Cyan
            {192, 192, 192},  // White
            {128, 128, 128},  // Bright Black
            {255, 0, 0},      // Bright Red
            {0, 255, 0},      // Bright Green
            {255, 255, 0},    // Bright Yellow
            {0, 0, 255},      // Bright Blue
            {255, 0, 255},    // Bright Magenta
            {0, 255, 255},    // Bright Cyan
            {255, 255, 255}   // Bright White
        };
        return Color(standardColors[index][0], standardColors[index][1], standardColors[index][2]);
    } else if (index < 232) {
        // 216 color cube (16-231)
        uint8_t r = ((index - 16) / 36) * 51;
        uint8_t g = (((index - 16) % 36) / 6) * 51;
        uint8_t b = ((index - 16) % 6) * 51;
        return Color(r, g, b);
    } else {
        // Grayscale (232-255)
        uint8_t gray = (index - 232) * 10 + 8;
        return Color(gray, gray, gray);
    }
}

// ============================================================================
// ANSIParser Implementation
// ============================================================================
ANSIParser::ANSIParser() 
    : m_terminalSize{24, 80, 0, 0}
    , m_currentStyle()
    , m_defaultStyle() {
    
    m_defaultStyle.fg = Color(255, 255, 255);
    m_defaultStyle.bg = Color(0, 0, 0);
    m_currentStyle = m_defaultStyle;
    
    ResizeScreenBuffer();
}

ANSIParser::~ANSIParser() = default;

ANSIParser::ANSIParser(ANSIParser&& other) noexcept
    : m_terminalSize(other.m_terminalSize)
    , m_currentStyle(other.m_currentStyle)
    , m_defaultStyle(other.m_defaultStyle)
    , m_cursor(other.m_cursor)
    , m_savedCursor(other.m_savedCursor)
    , m_screenBuffer(std::move(other.m_screenBuffer))
    , m_screenBufferDirty(other.m_screenBufferDirty)
    , m_scrollback(std::move(other.m_scrollback))
    , m_maxScrollbackLines(other.m_maxScrollbackLines)
    , m_scrollbackEnabled(other.m_scrollbackEnabled)
    , m_parseBuffer(std::move(other.m_parseBuffer))
    , m_parsedSequenceCount(other.m_parsedSequenceCount)
    , m_currentHyperlinkId(std::move(other.m_currentHyperlinkId))
    , m_currentHyperlinkUrl(std::move(other.m_currentHyperlinkUrl))
    , m_state(other.m_state)
    , m_csiParams(std::move(other.m_csiParams))
    , m_csiIntermediate(std::move(other.m_csiIntermediate))
    , m_csiFinalChar(other.m_csiFinalChar)
    , m_oscParam(other.m_oscParam)
    , m_oscString(std::move(other.m_oscString)) {
}

ANSIParser& ANSIParser::operator=(ANSIParser&& other) noexcept {
    if (this != &other) {
        m_terminalSize = other.m_terminalSize;
        m_currentStyle = other.m_currentStyle;
        m_defaultStyle = other.m_defaultStyle;
        m_cursor = other.m_cursor;
        m_savedCursor = other.m_savedCursor;
        m_screenBuffer = std::move(other.m_screenBuffer);
        m_screenBufferDirty = other.m_screenBufferDirty;
        m_scrollback = std::move(other.m_scrollback);
        m_maxScrollbackLines = other.m_maxScrollbackLines;
        m_scrollbackEnabled = other.m_scrollbackEnabled;
        m_parseBuffer = std::move(other.m_parseBuffer);
        m_parsedSequenceCount = other.m_parsedSequenceCount;
        m_currentHyperlinkId = std::move(other.m_currentHyperlinkId);
        m_currentHyperlinkUrl = std::move(other.m_currentHyperlinkUrl);
        m_state = other.m_state;
        m_csiParams = std::move(other.m_csiParams);
        m_csiIntermediate = std::move(other.m_csiIntermediate);
        m_csiFinalChar = other.m_csiFinalChar;
        m_oscParam = other.m_oscParam;
        m_oscString = std::move(other.m_oscString);
    }
    return *this;
}

void ANSIParser::SetTerminalSize(int rows, int cols) {
    if (rows < 1) rows = 1;
    if (cols < 1) cols = 1;
    
    m_terminalSize.rows = rows;
    m_terminalSize.cols = cols;
    ResizeScreenBuffer();
}

void ANSIParser::ResizeScreenBuffer() {
    size_t newSize = m_terminalSize.rows * m_terminalSize.cols;
    auto newBuffer = std::make_unique<ScreenCell[]>(newSize);
    
    // Initialize new buffer
    for (int i = 0; i < newSize; ++i) {
        newBuffer[i].Clear();
    }
    
    // Copy old buffer if exists
    if (m_screenBuffer) {
        int minRows = std::min(m_terminalSize.rows, 
            static_cast<int>(m_scrollback.size() > 0 ? m_scrollback.size() : m_terminalSize.rows));
        int minCols = m_terminalSize.cols;
        
        for (int row = 0; row < minRows; ++row) {
            for (int col = 0; col < minCols; ++col) {
                int oldIdx = row * m_terminalSize.cols + col;
                int newIdx = row * m_terminalSize.cols + col;
                if (oldIdx < newSize && newIdx < newSize) {
                    newBuffer[newIdx] = m_screenBuffer[oldIdx];
                }
            }
        }
    }
    
    m_screenBuffer = std::move(newBuffer);
    m_screenBufferDirty = true;
}

std::vector<TextFragment> ANSIParser::Parse(const std::string& input) {
    std::vector<TextFragment> fragments;
    
    for (char c : input) {
        ProcessChar(c);
        
        // Collect fragments when we have text and hit an escape sequence
        if (m_state == ParseState::Escape && !m_parseBuffer.empty()) {
            fragments.emplace_back(m_parseBuffer, m_currentStyle);
            m_parseBuffer.clear();
        }
    }
    
    // Flush remaining buffer
    if (!m_parseBuffer.empty()) {
        fragments.emplace_back(m_parseBuffer, m_currentStyle);
        m_parseBuffer.clear();
    }
    
    return fragments;
}

void ANSIParser::ParseIncremental(const std::string& chunk, 
                                   std::function<void(const TextFragment&)> onFragment) {
    for (char c : chunk) {
        ProcessChar(c);
        
        if (m_state == ParseState::Escape && !m_parseBuffer.empty()) {
            onFragment(TextFragment(m_parseBuffer, m_currentStyle));
            m_parseBuffer.clear();
        }
    }
}

void ANSIParser::ProcessChar(char c) {
    switch (m_state) {
        case ParseState::Normal:
            ProcessNormalChar(c);
            break;
            
        case ParseState::Escape:
            ProcessEscapeChar(c);
            break;
            
        case ParseState::CSI:
        case ParseState::CSI_Params:
            ProcessCSIChar(c);
            break;
            
        case ParseState::OSC:
        case ParseState::OSC_Params:
        case ParseState::OSC_ST:
            ProcessOSCChar(c);
            break;
            
        case ParseState::DCS:
        case ParseState::DCS_Params:
        case ParseState::DCS_ST:
            // Device Control String - ignore for now
            if (c == '\x07' || (c == '\x9c') || (c == '\x1b' && m_parseBuffer.empty())) {
                m_state = ParseState::Normal;
                m_parseBuffer.clear();
            }
            break;
            
        case ParseState::Ignore:
            // Ignore until terminator
            if (c == '\x07' || c == '\x9c' || c == '\x1b') {
                m_state = ParseState::Normal;
            }
            break;
            
        default:
            m_state = ParseState::Normal;
            ProcessNormalChar(c);
            break;
    }
}

void ANSIParser::ProcessNormalChar(char c) {
    if (c == '\x1b') {
        // Start of escape sequence
        if (!m_parseBuffer.empty()) {
            // Flush current text
            // (handled by caller)
        }
        m_state = ParseState::Escape;
    } else if (c == '\x07') {
        // Bell - ignore
    } else if (c == '\x08') {
        // Backspace
        if (!m_parseBuffer.empty()) {
            m_parseBuffer.pop_back();
        }
    } else if (c == '\r') {
        // Carriage return
        // Remove everything after last newline
        size_t lastNL = m_parseBuffer.find_last_of('\n');
        if (lastNL != std::string::npos) {
            m_parseBuffer.erase(lastNL + 1);
        } else {
            m_parseBuffer.clear();
        }
    } else if (c == '\n') {
        // Line feed
        m_parseBuffer += c;
    } else if (c == '\t') {
        // Tab - expand to spaces
        size_t currentCol = m_parseBuffer.length();
        size_t spaces = 8 - (currentCol % 8);
        m_parseBuffer.append(spaces, ' ');
    } else if (c >= 0x20 || c == 0x09) {
        // Printable character
        m_parseBuffer += c;
    }
    // Ignore other control characters
}

void ANSIParser::ProcessEscapeChar(char c) {
    switch (c) {
        case '[':
            m_state = ParseState::CSI;
            m_csiParams.clear();
            m_csiIntermediate.clear();
            m_csiFinalChar = 0;
            break;
            
        case ']':
            m_state = ParseState::OSC;
            m_oscParam = 0;
            m_oscString.clear();
            break;
            
        case 'P':
            m_state = ParseState::DCS;
            break;
            
        case '_':
            m_state = ParseState::APC;
            break;
            
        case '^':
            m_state = ParseState::PM;
            break;
            
        case '\\':
            // ST (String Terminator)
            m_state = ParseState::Normal;
            break;
            
        case '(':
        case ')':
        case '*':
        case '+':
            // Character set selection
            m_state = ParseState::Charset;
            break;
            
        case '7':
            // DECSC - Save cursor
            SaveCursorPosition();
            m_state = ParseState::Normal;
            break;
            
        case '8':
            // DECRC - Restore cursor
            RestoreCursorPosition();
            m_state = ParseState::Normal;
            break;
            
        case 'c':
            // RIS - Full reset
            Reset();
            m_state = ParseState::Normal;
            break;
            
        case 'M':
            // RI - Reverse index
            if (m_cursor.row > 0) {
                m_cursor.row--;
            }
            m_state = ParseState::Normal;
            break;
            
        default:
            // Unknown escape sequence, ignore
            m_state = ParseState::Normal;
            break;
    }
}

void ANSIParser::ProcessCSIChar(char c) {
    if (IsCSIParamChar(c)) {
        // Parameter byte
        m_state = ParseState::CSI_Params;
        if (m_csiParams.empty()) m_csiParams.push_back(0);
        
        if (c >= '0' && c <= '9') {
            m_csiParams.back() = m_csiParams.back() * 10 + (c - '0');
        } else if (c == ';') {
            m_csiParams.push_back(0);
        } else if (c == ':') {
            // Sub-parameter (rarely used)
        }
    } else if (IsCSIIntermediateChar(c)) {
        // Intermediate byte
        m_csiIntermediate += c;
    } else if (IsCSIFinalChar(c)) {
        // Final byte
        m_csiFinalChar = c;
        ExecuteCSI();
        m_state = ParseState::Normal;
    } else {
        // Invalid, abort
        m_state = ParseState::Normal;
    }
}

void ANSIParser::ProcessOSCChar(char c) {
    if (m_state == ParseState::OSC) {
        if (c >= '0' && c <= '9') {
            m_oscParam = m_oscParam * 10 + (c - '0');
        } else if (c == ';') {
            m_state = ParseState::OSC_Params;
        } else if (c == '\x07' || c == '\x1b') {
            // End of OSC
            ExecuteOSC();
            m_state = ParseState::Normal;
        }
    } else if (m_state == ParseState::OSC_Params) {
        if (c == '\x07') {
            // BEL ends OSC
            ExecuteOSC();
            m_state = ParseState::Normal;
        } else if (c == '\x1b') {
            // ESC might start ST
            m_state = ParseState::OSC_ST;
        } else {
            m_oscString += c;
        }
    } else if (m_state == ParseState::OSC_ST) {
        if (c == '\\') {
            // ST complete
            ExecuteOSC();
            m_state = ParseState::Normal;
        } else {
            // Not ST, add to string
            m_oscString += '\x1b';
            m_oscString += c;
            m_state = ParseState::OSC_Params;
        }
    }
}

void ANSIParser::ExecuteCSI() {
    m_parsedSequenceCount++;
    
    // Default parameter values
    auto param = [&](size_t idx, int defaultVal) -> int {
        if (idx < m_csiParams.size()) {
            return m_csiParams[idx] == 0 ? defaultVal : m_csiParams[idx];
        }
        return defaultVal;
    };
    
    switch (m_csiFinalChar) {
        case 'm':
            // SGR - Select Graphic Rendition
            ExecuteSGR(m_csiParams);
            break;
            
        case 'H':
        case 'f': {
            // CUP - Cursor Position
            int row = param(0, 1) - 1;
            int col = param(1, 1) - 1;
            SetCursorPosition(row, col);
            break;
        }
        
        case 'A': {
            // CUU - Cursor Up
            int n = param(0, 1);
            MoveCursor(-n, 0);
            break;
        }
        
        case 'B': {
            // CUD - Cursor Down
            int n = param(0, 1);
            MoveCursor(n, 0);
            break;
        }
        
        case 'C': {
            // CUF - Cursor Forward
            int n = param(0, 1);
            MoveCursor(0, n);
            break;
        }
        
        case 'D': {
            // CUB - Cursor Back
            int n = param(0, 1);
            MoveCursor(0, -n);
            break;
        }
        
        case 'E': {
            // CNL - Cursor Next Line
            int n = param(0, 1);
            m_cursor.row = ClampRow(m_cursor.row + n);
            m_cursor.col = 0;
            break;
        }
        
        case 'F': {
            // CPL - Cursor Previous Line
            int n = param(0, 1);
            m_cursor.row = ClampRow(m_cursor.row - n);
            m_cursor.col = 0;
            break;
        }
        
        case 'G': {
            // CHA - Cursor Horizontal Absolute
            int col = param(0, 1) - 1;
            m_cursor.col = ClampCol(col);
            break;
        }
        
        case 'J': {
            // ED - Erase in Display
            int n = param(0, 0);
            switch (n) {
                case 0: ClearToEndOfLine(); break;
                case 1: ClearToStartOfLine(); break;
                case 2: ClearScreen(); break;
                case 3: ClearScreen(); break; // Clear scrollback too
            }
            break;
        }
        
        case 'K': {
            // EL - Erase in Line
            int n = param(0, 0);
            switch (n) {
                case 0: ClearToEndOfLine(); break;
                case 1: ClearToStartOfLine(); break;
                case 2: ClearLine(); break;
            }
            break;
        }
        
        case 'S': {
            // SU - Scroll Up
            int n = param(0, 1);
            ScrollUp(n);
            break;
        }
        
        case 'T': {
            // SD - Scroll Down
            int n = param(0, 1);
            ScrollDown(n);
            break;
        }
        
        case 'L': {
            // IL - Insert Line
            int n = param(0, 1);
            InsertLines(n);
            break;
        }
        
        case 'M': {
            // DL - Delete Line
            int n = param(0, 1);
            DeleteLines(n);
            break;
        }
        
        case '@': {
            // ICH - Insert Character
            int n = param(0, 1);
            InsertChars(n);
            break;
        }
        
        case 'P': {
            // DCH - Delete Character
            int n = param(0, 1);
            DeleteChars(n);
            break;
        }
        
        case 'X': {
            // ECH - Erase Character
            int n = param(0, 1);
            EraseChars(n);
            break;
        }
        
        case 's':
            // SCP - Save Cursor Position
            SaveCursorPosition();
            break;
            
        case 'u':
            // RCP - Restore Cursor Position
            RestoreCursorPosition();
            break;
            
        case 'h':
        case 'l':
            // SM/RM - Set/Reset Mode (simplified)
            break;
            
        default:
            // Unknown CSI sequence
            break;
    }
}

void ANSIParser::ExecuteOSC() {
    m_parsedSequenceCount++;
    
    switch (m_oscParam) {
        case 0:
        case 2:
            // Set window title
            break;
            
        case 8: {
            // Hyperlink (OSC 8 ; params ; URI ST)
            size_t sep = m_oscString.find(';');
            if (sep != std::string::npos) {
                std::string params = m_oscString.substr(0, sep);
                std::string uri = m_oscString.substr(sep + 1);
                
                // Parse params for id
                size_t idPos = params.find("id=");
                if (idPos != std::string::npos) {
                    m_currentHyperlinkId = params.substr(idPos + 3);
                }
                m_currentHyperlinkUrl = uri;
                
                if (m_hyperlinkCallback) {
                    m_hyperlinkCallback(m_currentHyperlinkId, m_currentHyperlinkUrl, 
                                       m_cursor.row, m_cursor.col);
                }
            }
            break;
        }
        
        case 10:
        case 11:
        case 12:
            // Set foreground/background/cursor color
            break;
            
        default:
            break;
    }
}

void ANSIParser::ExecuteSGR(const std::vector<int>& params) {
    if (params.empty()) {
        m_currentStyle.Reset();
        return;
    }
    
    for (size_t i = 0; i < params.size(); ++i) {
        int code = params[i];
        
        switch (code) {
            case 0: m_currentStyle.Reset(); break;
            case 1: m_currentStyle.bold = true; break;
            case 2: m_currentStyle.faint = true; break;
            case 3: m_currentStyle.italic = true; break;
            case 4: m_currentStyle.underline = true; m_currentStyle.underlineStyle = TextStyle::Single; break;
            case 5: m_currentStyle.blink = true; break;
            case 7: m_currentStyle.reverse = true; break;
            case 8: m_currentStyle.conceal = true; break;
            case 9: m_currentStyle.strikethrough = true; break;
            case 21: m_currentStyle.underline = true; m_currentStyle.underlineStyle = TextStyle::Double; break;
            case 22: m_currentStyle.bold = false; m_currentStyle.faint = false; break;
            case 23: m_currentStyle.italic = false; break;
            case 24: m_currentStyle.underline = false; m_currentStyle.underlineStyle = TextStyle::None; break;
            case 25: m_currentStyle.blink = false; break;
            case 27: m_currentStyle.reverse = false; break;
            case 28: m_currentStyle.conceal = false; break;
            case 29: m_currentStyle.strikethrough = false; break;
            
            // Foreground colors
            case 30: m_currentStyle.fg = Color::From8Bit(0); break;
            case 31: m_currentStyle.fg = Color::From8Bit(1); break;
            case 32: m_currentStyle.fg = Color::From8Bit(2); break;
            case 33: m_currentStyle.fg = Color::From8Bit(3); break;
            case 34: m_currentStyle.fg = Color::From8Bit(4); break;
            case 35: m_currentStyle.fg = Color::From8Bit(5); break;
            case 36: m_currentStyle.fg = Color::From8Bit(6); break;
            case 37: m_currentStyle.fg = Color::From8Bit(7); break;
            case 39: m_currentStyle.fg = m_defaultStyle.fg; break;
            
            // Background colors
            case 40: m_currentStyle.bg = Color::From8Bit(0); break;
            case 41: m_currentStyle.bg = Color::From8Bit(1); break;
            case 42: m_currentStyle.bg = Color::From8Bit(2); break;
            case 43: m_currentStyle.bg = Color::From8Bit(3); break;
            case 44: m_currentStyle.bg = Color::From8Bit(4); break;
            case 45: m_currentStyle.bg = Color::From8Bit(5); break;
            case 46: m_currentStyle.bg = Color::From8Bit(6); break;
            case 47: m_currentStyle.bg = Color::From8Bit(7); break;
            case 49: m_currentStyle.bg = m_defaultStyle.bg; break;
            
            // Bright foreground colors
            case 90: m_currentStyle.fg = Color::From8Bit(8); break;
            case 91: m_currentStyle.fg = Color::From8Bit(9); break;
            case 92: m_currentStyle.fg = Color::From8Bit(10); break;
            case 93: m_currentStyle.fg = Color::From8Bit(11); break;
            case 94: m_currentStyle.fg = Color::From8Bit(12); break;
            case 95: m_currentStyle.fg = Color::From8Bit(13); break;
            case 96: m_currentStyle.fg = Color::From8Bit(14); break;
            case 97: m_currentStyle.fg = Color::From8Bit(15); break;
            
            // Bright background colors
            case 100: m_currentStyle.bg = Color::From8Bit(8); break;
            case 101: m_currentStyle.bg = Color::From8Bit(9); break;
            case 102: m_currentStyle.bg = Color::From8Bit(10); break;
            case 103: m_currentStyle.bg = Color::From8Bit(11); break;
            case 104: m_currentStyle.bg = Color::From8Bit(12); break;
            case 105: m_currentStyle.bg = Color::From8Bit(13); break;
            case 106: m_currentStyle.bg = Color::From8Bit(14); break;
            case 107: m_currentStyle.bg = Color::From8Bit(15); break;
            
            // 256 colors and RGB
            case 38:
                if (i + 1 < params.size()) {
                    if (params[i + 1] == 5 && i + 2 < params.size()) {
                        // 256 color
                        m_currentStyle.fg = Color::From8Bit(static_cast<uint8_t>(params[i + 2]));
                        i += 2;
                    } else if (params[i + 1] == 2 && i + 4 < params.size()) {
                        // RGB
                        m_currentStyle.fg = Color(params[i + 2], params[i + 3], params[i + 4]);
                        i += 4;
                    }
                }
                break;
                
            case 48:
                if (i + 1 < params.size()) {
                    if (params[i + 1] == 5 && i + 2 < params.size()) {
                        m_currentStyle.bg = Color::From8Bit(static_cast<uint8_t>(params[i + 2]));
                        i += 2;
                    } else if (params[i + 1] == 2 && i + 4 < params.size()) {
                        m_currentStyle.bg = Color(params[i + 2], params[i + 3], params[i + 4]);
                        i += 4;
                    }
                }
                break;
                
            default:
                break;
        }
    }
}

// ============================================================================
// Screen Operations
// ============================================================================
void ANSIParser::ParseToScreen(const std::string& input) {
    for (char c : input) {
        ProcessChar(c);
        
        // Write to screen buffer in normal mode
        if (m_state == ParseState::Normal && !m_parseBuffer.empty()) {
            for (char ch : m_parseBuffer) {
                if (ch == '\n') {
                    m_cursor.row++;
                    m_cursor.col = 0;
                    if (m_cursor.row >= m_terminalSize.rows) {
                        ScrollUp(1);
                        m_cursor.row = m_terminalSize.rows - 1;
                    }
                } else if (ch == '\r') {
                    m_cursor.col = 0;
                } else if (ch >= 0x20) {
                    SetCell(m_cursor.row, m_cursor.col, ch, m_currentStyle);
                    m_cursor.col++;
                    if (m_cursor.col >= m_terminalSize.cols) {
                        m_cursor.col = 0;
                        m_cursor.row++;
                        if (m_cursor.row >= m_terminalSize.rows) {
                            ScrollUp(1);
                            m_cursor.row = m_terminalSize.rows - 1;
                        }
                    }
                }
            }
            m_parseBuffer.clear();
        }
    }
}

void ANSIParser::SetCell(int row, int col, char32_t ch, const TextStyle& style) {
    if (!IsValidPosition(row, col)) return;
    
    ScreenCell& cell = GetCell(row, col);
    cell.character = ch;
    cell.style = style;
    cell.dirty = true;
    m_screenBufferDirty = true;
}

ScreenCell& ANSIParser::GetCell(int row, int col) {
    return m_screenBuffer[row * m_terminalSize.cols + col];
}

bool ANSIParser::IsValidPosition(int row, int col) const {
    return row >= 0 && row < m_terminalSize.rows &&
           col >= 0 && col < m_terminalSize.cols;
}

void ANSIParser::ScrollUp(int lines) {
    if (lines <= 0) return;
    
    // Save scrolled lines to scrollback
    if (m_scrollbackEnabled) {
        for (int i = 0; i < lines && i < m_terminalSize.rows; ++i) {
            AppendToScrollback(GetLine(i));
        }
    }
    
    // Move lines up
    int moveCount = (m_terminalSize.rows - lines) * m_terminalSize.cols;
    if (moveCount > 0) {
        memmove(m_screenBuffer.get(), 
                m_screenBuffer.get() + lines * m_terminalSize.cols,
                moveCount * sizeof(ScreenCell));
    }
    
    // Clear new lines at bottom
    for (int row = m_terminalSize.rows - lines; row < m_terminalSize.rows; ++row) {
        for (int col = 0; col < m_terminalSize.cols; ++col) {
            GetCell(row, col).Clear();
        }
    }
    
    m_screenBufferDirty = true;
}

void ANSIParser::ScrollDown(int lines) {
    if (lines <= 0) return;
    
    // Move lines down
    int moveCount = (m_terminalSize.rows - lines) * m_terminalSize.cols;
    if (moveCount > 0) {
        memmove(m_screenBuffer.get() + lines * m_terminalSize.cols,
                m_screenBuffer.get(),
                moveCount * sizeof(ScreenCell));
    }
    
    // Clear new lines at top
    for (int row = 0; row < lines; ++row) {
        for (int col = 0; col < m_terminalSize.cols; ++col) {
            GetCell(row, col).Clear();
        }
    }
    
    m_screenBufferDirty = true;
}

void ANSIParser::InsertLines(int count) {
    if (count <= 0) return;
    int endRow = m_terminalSize.rows;
    int linesToMove = endRow - m_cursor.row - count;
    
    if (linesToMove > 0) {
        memmove(m_screenBuffer.get() + (m_cursor.row + count) * m_terminalSize.cols,
                m_screenBuffer.get() + m_cursor.row * m_terminalSize.cols,
                linesToMove * m_terminalSize.cols * sizeof(ScreenCell));
    }
    
    // Clear inserted lines
    for (int row = m_cursor.row; row < m_cursor.row + count && row < endRow; ++row) {
        for (int col = 0; col < m_terminalSize.cols; ++col) {
            GetCell(row, col).Clear();
        }
    }
    
    m_screenBufferDirty = true;
}

void ANSIParser::DeleteLines(int count) {
    if (count <= 0) return;
    int endRow = m_terminalSize.rows;
    int linesToMove = endRow - m_cursor.row - count;
    
    if (linesToMove > 0) {
        memmove(m_screenBuffer.get() + m_cursor.row * m_terminalSize.cols,
                m_screenBuffer.get() + (m_cursor.row + count) * m_terminalSize.cols,
                linesToMove * m_terminalSize.cols * sizeof(ScreenCell));
    }
    
    // Clear lines at bottom
    for (int row = endRow - count; row < endRow; ++row) {
        for (int col = 0; col < m_terminalSize.cols; ++col) {
            GetCell(row, col).Clear();
        }
    }
    
    m_screenBufferDirty = true;
}

void ANSIParser::InsertChars(int count) {
    if (count <= 0) return;
    int row = m_cursor.row;
    int startCol = m_cursor.col;
    int charsToMove = m_terminalSize.cols - startCol - count;
    
    if (charsToMove > 0) {
        for (int i = m_terminalSize.cols - 1; i >= startCol + count; --i) {
            GetCell(row, i) = GetCell(row, i - count);
        }
    }
    
    // Clear inserted chars
    for (int col = startCol; col < startCol + count && col < m_terminalSize.cols; ++col) {
        GetCell(row, col).Clear();
    }
    
    m_screenBufferDirty = true;
}

void ANSIParser::DeleteChars(int count) {
    if (count <= 0) return;
    int row = m_cursor.row;
    int startCol = m_cursor.col;
    int charsToMove = m_terminalSize.cols - startCol - count;
    
    if (charsToMove > 0) {
        for (int col = startCol; col < m_terminalSize.cols - count; ++col) {
            GetCell(row, col) = GetCell(row, col + count);
        }
    }
    
    // Clear chars at end
    for (int col = m_terminalSize.cols - count; col < m_terminalSize.cols; ++col) {
        GetCell(row, col).Clear();
    }
    
    m_screenBufferDirty = true;
}

void ANSIParser::EraseChars(int count) {
    if (count <= 0) return;
    int row = m_cursor.row;
    int startCol = m_cursor.col;
    
    for (int col = startCol; col < startCol + count && col < m_terminalSize.cols; ++col) {
        GetCell(row, col).Clear();
    }
    
    m_screenBufferDirty = true;
}

// ============================================================================
// State Management
// ============================================================================
void ANSIParser::Reset() {
    m_currentStyle = m_defaultStyle;
    m_cursor = CursorState();
    m_savedCursor = CursorState();
    ClearScreen();
    m_state = ParseState::Normal;
    m_csiParams.clear();
    m_csiIntermediate.clear();
    m_csiFinalChar = 0;
    m_oscParam = 0;
    m_oscString.clear();
    m_parseBuffer.clear();
    m_currentHyperlinkId.clear();
    m_currentHyperlinkUrl.clear();
}

void ANSIParser::ClearScreen() {
    for (int i = 0; i < m_terminalSize.rows * m_terminalSize.cols; ++i) {
        m_screenBuffer[i].Clear();
    }
    m_cursor.row = 0;
    m_cursor.col = 0;
    m_screenBufferDirty = true;
}

void ANSIParser::ClearLine() {
    int row = m_cursor.row;
    for (int col = 0; col < m_terminalSize.cols; ++col) {
        GetCell(row, col).Clear();
    }
    m_screenBufferDirty = true;
}

void ANSIParser::ClearToEndOfLine() {
    int row = m_cursor.row;
    for (int col = m_cursor.col; col < m_terminalSize.cols; ++col) {
        GetCell(row, col).Clear();
    }
    m_screenBufferDirty = true;
}

void ANSIParser::ClearToStartOfLine() {
    int row = m_cursor.row;
    for (int col = 0; col <= m_cursor.col; ++col) {
        GetCell(row, col).Clear();
    }
    m_screenBufferDirty = true;
}

void ANSIParser::SetCursorPosition(int row, int col) {
    m_cursor.row = ClampRow(row);
    m_cursor.col = ClampCol(col);
}

void ANSIParser::MoveCursor(int deltaRow, int deltaCol) {
    m_cursor.row = ClampRow(m_cursor.row + deltaRow);
    m_cursor.col = ClampCol(m_cursor.col + deltaCol);
}

void ANSIParser::SaveCursorPosition() {
    m_savedCursor = m_cursor;
}

void ANSIParser::RestoreCursorPosition() {
    m_cursor = m_savedCursor;
}

// ============================================================================
// Scrollback
// ============================================================================
void ANSIParser::EnableScrollback(size_t maxLines) {
    m_scrollbackEnabled = true;
    m_maxScrollbackLines = maxLines;
}

void ANSIParser::DisableScrollback() {
    m_scrollbackEnabled = false;
    m_scrollback.clear();
}

void ANSIParser::ClearScrollback() {
    m_scrollback.clear();
}

void ANSIParser::AppendToScrollback(const std::string& line) {
    if (!m_scrollbackEnabled) return;
    
    m_scrollback.push_back(line);
    
    // Trim if exceeds max
    while (m_scrollback.size() > m_maxScrollbackLines) {
        m_scrollback.erase(m_scrollback.begin());
    }
}

// ============================================================================
// Utility
// ============================================================================
std::string ANSIParser::GetScreenText(int startRow, int startCol, int endRow, int endCol) const {
    std::string result;
    for (int row = startRow; row <= endRow && row < m_terminalSize.rows; ++row) {
        int colStart = (row == startRow) ? startCol : 0;
        int colEnd = (row == endRow) ? endCol : m_terminalSize.cols - 1;
        
        for (int col = colStart; col <= colEnd && col < m_terminalSize.cols; ++col) {
            char32_t ch = m_screenBuffer[row * m_terminalSize.cols + col].character;
            if (ch <= 0x7F) {
                result += static_cast<char>(ch);
            }
        }
        
        if (row < endRow) {
            result += '\n';
        }
    }
    return result;
}

std::string ANSIParser::GetLine(int row) const {
    if (row < 0 || row >= m_terminalSize.rows) return "";
    
    std::string result;
    for (int col = 0; col < m_terminalSize.cols; ++col) {
        char32_t ch = m_screenBuffer[row * m_terminalSize.cols + col].character;
        if (ch <= 0x7F) {
            result += static_cast<char>(ch);
        }
    }
    
    // Trim trailing spaces
    while (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    
    return result;
}

int ANSIParser::ClampRow(int row) const {
    if (row < 0) return 0;
    if (row >= m_terminalSize.rows) return m_terminalSize.rows - 1;
    return row;
}

int ANSIParser::ClampCol(int col) const {
    if (col < 0) return 0;
    if (col >= m_terminalSize.cols) return m_terminalSize.cols - 1;
    return col;
}

bool ANSIParser::IsCSIParamChar(char c) {
    return (c >= '0' && c <= '9') || c == ';' || c == ':' || c == '<' || c == '=' || c == '>' || c == '?';
}

bool ANSIParser::IsCSIIntermediateChar(char c) {
    return (c >= 0x20 && c <= 0x2F);
}

bool ANSIParser::IsCSIFinalChar(char c) {
    return (c >= 0x40 && c <= 0x7E);
}

std::string ANSIParser::GetDebugInfo() const {
    std::ostringstream oss;
    oss << "ANSIParser State:\n";
    oss << "  Terminal: " << m_terminalSize.rows << "x" << m_terminalSize.cols << "\n";
    oss << "  Cursor: (" << m_cursor.row << "," << m_cursor.col << ")\n";
    oss << "  State: " << static_cast<int>(m_state) << "\n";
    oss << "  Parsed sequences: " << m_parsedSequenceCount << "\n";
    oss << "  Scrollback lines: " << m_scrollback.size() << "\n";
    return oss.str();
}

// ============================================================================
// Utility Functions
// ============================================================================
std::string StripANSICodes(const std::string& input) {
    ANSIParser parser;
    auto fragments = parser.Parse(input);
    
    std::string result;
    for (const auto& frag : fragments) {
        result += frag.text;
    }
    return result;
}

bool ContainsANSICodes(const std::string& input) {
    return input.find('\x1b') != std::string::npos;
}

size_t GetVisibleLength(const std::string& input) {
    return StripANSICodes(input).length();
}

std::string TruncateVisible(const std::string& input, size_t maxLen) {
    ANSIParser parser;
    auto fragments = parser.Parse(input);
    
    std::string result;
    size_t visibleLen = 0;
    
    for (const auto& frag : fragments) {
        if (visibleLen + frag.text.length() <= maxLen) {
            result += frag.text;
            visibleLen += frag.text.length();
        } else {
            size_t remaining = maxLen - visibleLen;
            result += frag.text.substr(0, remaining);
            break;
        }
    }
    
    return result;
}

std::string PadVisible(const std::string& input, size_t targetLen, char padChar) {
    size_t visibleLen = GetVisibleLength(input);
    if (visibleLen >= targetLen) return input;
    
    return input + std::string(targetLen - visibleLen, padChar);
}

} // namespace rawrxd::terminal
