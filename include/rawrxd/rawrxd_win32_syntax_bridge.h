#pragma once

// RawrXD Win32 Syntax Bridge — Win32-specific syntax highlighting integration
// Gated by RAWRXD_SOFTWARE_BLIT_RASTER=1.

#include "rawrxd/rawrxd_syntax_bridge.h"

#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace rawrxd::ui
{

// Win32 editor handle wrapper
struct Win32EditorHandle
{
    HWND hwnd = nullptr;
    HFONT font = nullptr;
    HDC hdc = nullptr;
    int lineHeight = 0;
    int charWidth = 0;
    int tabWidth = 4;
};

// Win32 syntax bridge context
struct Win32SyntaxBridgeContext
{
    SyntaxBridgeContext syntaxCtx;
    Win32EditorHandle editor;
    COLORREF backgroundColor = RGB(30, 30, 30);
    COLORREF selectionColor = RGB(38, 79, 120);
    COLORREF caretColor = RGB(255, 255, 255);
};

// Initialize Win32 syntax bridge
bool initializeWin32SyntaxBridge(Win32SyntaxBridgeContext* ctx, HWND hwndEditor, HFONT font);

// Shutdown Win32 syntax bridge
void shutdownWin32SyntaxBridge(Win32SyntaxBridgeContext* ctx);

// Get line text from RichEdit control
bool getRichEditLineText(HWND hwndEditor, int lineIndex, char* buffer, int bufferSize);

// Get line count from RichEdit
int getRichEditLineCount(HWND hwndEditor);

// Get current selection from RichEdit
void getRichEditSelection(HWND hwndEditor, int* startLine, int* startCol, int* endLine, int* endCol);

// Set RichEdit selection
void setRichEditSelection(HWND hwndEditor, int startLine, int startCol, int endLine, int endCol);

// Get visible line range from RichEdit
void getRichEditVisibleRange(HWND hwndEditor, int* firstVisibleLine, int* visibleLineCount);

// Scroll RichEdit to line
void scrollRichEditToLine(HWND hwndEditor, int lineIndex);

// Invalidate RichEdit line range
void invalidateRichEditLines(HWND hwndEditor, int startLine, int endLine);

// Get RichEdit character metrics
bool getRichEditCharMetrics(HWND hwndEditor, int lineIndex, int charIndex, int* x, int* y, int* width, int* height);

// Convert client coordinates to line/column
bool clientToLineColumn(HWND hwndEditor, int clientX, int clientY, int* outLine, int* outColumn);

// Win32 syntax bridge enabled check
bool win32SyntaxBridgeEnabled();

} // namespace rawrxd::ui
