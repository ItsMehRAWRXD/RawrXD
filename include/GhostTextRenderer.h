// GhostTextRenderer.h
// RawrXD Win32IDE Ghost Text Overlay Renderer
// Non-blocking, alpha-blended overlay for inline completions

#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

// ─── Ghost Text Renderer Class ───
class GhostTextRenderer {
public:
    GhostTextRenderer() noexcept;
    ~GhostTextRenderer();

    // No copy
    GhostTextRenderer(const GhostTextRenderer&) = delete;
    GhostTextRenderer& operator=(const GhostTextRenderer&) = delete;

    // ─── Initialization ───
    bool Initialize(HWND hwnd, HFONT hFont);
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept { return m_hwnd != nullptr; }

    // ─── Ghost Text Management ───
    void ShowGhostText(const std::string& text, 
                       uint32_t line, 
                       uint32_t col,
                       uint32_t confidence = 5000);
    void Clear() noexcept;
    void UpdatePosition(uint32_t line, uint32_t col);

    // ─── Rendering ───
    void Render(HDC hdc);
    void GetGhostTextRect(RECT& outRect) const;

    // ─── Message Handling ───
    // Returns true if message was handled
    bool HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

    // ─── Commit/Reject ───
    std::wstring Commit();  // Returns ghost text and clears
    void Reject();          // Just clears
    bool IsVisible() const noexcept;

    // ─── Accessors ───
    uint32_t GetInsertLine() const noexcept { return m_insertLine; }
    uint32_t GetInsertCol() const noexcept { return m_insertCol; }
    uint32_t GetConfidence() const noexcept { return m_confidence; }

private:
    HWND m_hwnd;
    HFONT m_hFont;
    TEXTMETRICW m_textMetrics;
    int m_lineHeight;
    int m_charWidth;

    bool m_visible;
    std::wstring m_ghostText;
    uint32_t m_insertLine;
    uint32_t m_insertCol;
    uint32_t m_confidence;
};
