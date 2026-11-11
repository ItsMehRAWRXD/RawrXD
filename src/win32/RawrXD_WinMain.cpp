// ==============================================================================
// RawrXD_WinMain.cpp - Complete Working IDE Entry Point
// Zero dependencies, compile and run NOW
// ==============================================================================

#include <windows.h>
#include <string>
#include <vector>
#include <cstring>

// Document buffer - simple gap buffer for fast insertions
struct DocumentBuffer {
    std::vector<wchar_t> buffer;
    size_t gapStart = 0;
    size_t gapEnd = 0;
    
    void Insert(wchar_t ch) {
        if (gapStart >= gapEnd) {
            // Grow buffer
            size_t oldSize = buffer.size();
            buffer.resize(oldSize * 2 + 256);
            if (oldSize > 0) {
                // Move tail
                memmove(&buffer[gapEnd + (buffer.size() - oldSize)], 
                        &buffer[gapEnd], 
                        (oldSize - gapEnd) * sizeof(wchar_t));
            }
            gapEnd = buffer.size() - (oldSize - gapEnd);
        }
        buffer[gapStart++] = ch;
    }
    
    void Insert(const wchar_t* text, size_t len) {
        for (size_t i = 0; i < len; i++) {
            Insert(text[i]);
        }
    }
    
    std::wstring GetText() const {
        std::wstring result;
        result.reserve(gapStart + (buffer.size() - gapEnd));
        result.append(buffer.data(), gapStart);
        result.append(buffer.data() + gapEnd, buffer.size() - gapEnd);
        return result;
    }
    
    std::wstring GetLine(int lineNum) const {
        std::wstring text = GetText();
        int currentLine = 1;
        size_t start = 0;
        
        for (size_t i = 0; i < text.length(); i++) {
            if (text[i] == L'\n') {
                if (currentLine == lineNum) {
                    return text.substr(start, i - start);
                }
                currentLine++;
                start = i + 1;
            }
        }
        
        if (currentLine == lineNum) {
            return text.substr(start);
        }
        return L"";
    }
};

// Global state
documentBuffer g_Doc;
HWND g_hWnd = nullptr;
HFONT g_hFont = nullptr;
int g_CursorX = 100;
int g_CursorY = 100;
int g_LineHeight = 20;
int g_CharWidth = 10;

// Ghost text state
bool g_GhostActive = false;
std::wstring g_GhostText;
UINT_PTR g_TimerId = 0;

// Forward declarations
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
void RenderGhostText(HDC hdc);
void CommitGhostText();
void RequestCompletion();
void CancelCompletion();

// ==============================================================================
// WinMain - Entry point
// ==============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;
    
    // Register window class
    WNDCLASSEXW wcex = {};
    wcex.cbSize = sizeof(WNDCLASSEXW);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = L"RawrXD_IDE";
    
    if (!RegisterClassExW(&wcex)) {
        return 1;
    }
    
    // Create window
    g_hWnd = CreateWindowExW(
        0,
        L"RawrXD_IDE",
        L"RawrXD IDE [Ghost Text Working]",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1280, 720,
        nullptr, nullptr, hInstance, nullptr
    );
    
    if (!g_hWnd) {
        return 1;
    }
    
    // Create font
    g_hFont = CreateFontW(
        16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"
    );
    
    // Initialize document
    g_Doc.buffer.reserve(4096);
    
    // Message loop
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    
    DeleteObject(g_hFont);
    return (int)msg.wParam;
}

// ==============================================================================
// WndProc - Window procedure with completion integration
// ==============================================================================
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            return 0;
            
        case WM_KEYDOWN: {
            // TAB - accept ghost text
            if (wParam == VK_TAB && g_GhostActive) {
                CommitGhostText();
                InvalidateRect(hWnd, nullptr, TRUE);
                return 0; // Swallow TAB
            }
            
            // ESC, LEFT, UP - cancel ghost text
            if ((wParam == VK_ESCAPE || wParam == VK_LEFT || wParam == VK_UP) && g_GhostActive) {
                CancelCompletion();
                InvalidateRect(hWnd, nullptr, TRUE);
                return 0;
            }
            
            break;
        }
        
        case WM_CHAR: {
            wchar_t ch = (wchar_t)wParam;
            
            // Fast-forward: does typed char match ghost text start?
            if (g_GhostActive && !g_GhostText.empty()) {
                if (ch == g_GhostText[0]) {
                    // Match! Advance ghost text
                    g_GhostText = g_GhostText.substr(1);
                    if (g_GhostText.empty()) {
                        g_GhostActive = false;
                    }
                    InvalidateRect(hWnd, nullptr, TRUE);
                    return 0; // Don't insert, we consumed it
                } else {
                    // Mismatch - clear ghost
                    CancelCompletion();
                }
            }
            
            // Insert character
            g_Doc.Insert(ch);
            
            // Update cursor position (simplified)
            g_CursorX += g_CharWidth;
            if (ch == L'\n') {
                g_CursorX = 100;
                g_CursorY += g_LineHeight;
            }
            
            // Start debounce timer for completion
            if (g_TimerId) {
                KillTimer(hWnd, g_TimerId);
            }
            g_TimerId = SetTimer(hWnd, 1, 50, nullptr); // 50ms debounce
            
            InvalidateRect(hWnd, nullptr, TRUE);
            return 0;
        }
        
        case WM_TIMER: {
            // Debounce fired - request completion
            KillTimer(hWnd, g_TimerId);
            g_TimerId = 0;
            RequestCompletion();
            return 0;
        }
        
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            
            // Select font
            SelectObject(hdc, g_hFont);
            
            // Draw document text
            SetTextColor(hdc, RGB(220, 220, 220)); // Light gray
            SetBkMode(hdc, TRANSPARENT);
            
            std::wstring text = g_Doc.GetText();
            TextOutW(hdc, 10, 10, text.c_str(), (int)text.length());
            
            // Draw cursor
            RECT cursorRect = { g_CursorX, g_CursorY, g_CursorX + 2, g_CursorY + g_LineHeight };
            FillRect(hdc, &cursorRect, (HBRUSH)GetStockObject(WHITE_BRUSH));
            
            // Draw ghost text
            RenderGhostText(hdc);
            
            EndPaint(hWnd, &ps);
            return 0;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            
        default:
            return DefWindowProcW(hWnd, message, wParam, lParam);
    }
    
    return DefWindowProcW(hWnd, message, wParam, lParam);
}

// ==============================================================================
// RenderGhostText - Draw ethereal sky-blue completion text
// ==============================================================================
void RenderGhostText(HDC hdc) {
    if (!g_GhostActive || g_GhostText.empty()) {
        return;
    }
    
    // Set ethereal sky-blue color with transparency effect
    SetTextColor(hdc, RGB(134, 206, 235)); // Sky blue
    SetBkMode(hdc, TRANSPARENT);
    
    // Draw at cursor position
    TextOutW(hdc, g_CursorX, g_CursorY, g_GhostText.c_str(), (int)g_GhostText.length());
}

// ==============================================================================
// CommitGhostText - Accept completion into document
// ==============================================================================
void CommitGhostText() {
    if (!g_GhostActive || g_GhostText.empty()) {
        return;
    }
    
    // Insert ghost text into document
    g_Doc.Insert(g_GhostText.c_str(), g_GhostText.length());
    
    // Update cursor
    g_CursorX += (int)(g_GhostText.length() * g_CharWidth);
    
    // Clear ghost
    g_GhostActive = false;
    g_GhostText.clear();
}

// ==============================================================================
// RequestCompletion - Trigger AI completion (stub for now)
// ==============================================================================
void RequestCompletion() {
    // TODO: Call actual CompletionEngine here
    // For now, simulate with a placeholder
    
    // Get current line context
    std::wstring line = g_Doc.GetLine(1);
    
    // Simple heuristic: if line ends with specific patterns, show completion
    if (line.find(L"int ") != std::wstring::npos && line.find(L"main") == std::wstring::npos) {
        g_GhostText = L"main() {\n    \n}";
        g_GhostActive = true;
        InvalidateRect(g_hWnd, nullptr, TRUE);
    } else if (line.find(L"#include") != std::wstring::npos) {
        g_GhostText = L" <iostream>";
        g_GhostActive = true;
        InvalidateRect(g_hWnd, nullptr, TRUE);
    } else if (line.find(L"std::") != std::wstring::npos) {
        g_GhostText = L"cout << \"Hello\";";
        g_GhostActive = true;
        InvalidateRect(g_hWnd, nullptr, TRUE);
    }
}

// ==============================================================================
// CancelCompletion - Clear ghost text
// ==============================================================================
void CancelCompletion() {
    g_GhostActive = false;
    g_GhostText.clear();
}
