// CursorWidget — Win32/native. No Qt. Presence cursors for collaboration.

#include "collab/cursor_widget.h"
#include <windows.h>

CursorWidget::CursorWidget(void* parentHandle)
    : m_handle(parentHandle)
{
}

void CursorWidget::updateCursor(const std::string& userId, const CursorInfo& info)
{
    m_cursors[userId] = info;
    if (m_handle) {
        InvalidateRect((HWND)m_handle, nullptr, TRUE);
    }
}

void CursorWidget::removeCursor(const std::string& userId)
{
    m_cursors.erase(userId);
    if (m_handle) {
        InvalidateRect((HWND)m_handle, nullptr, TRUE);
    }
}

void CursorWidget::paint(HDC hdc)
{
    for (const auto& kv : m_cursors) {
        const CursorInfo& info = kv.second;
        // Simple cursor rendering: draw a small colored rectangle at position
        // In a real implementation, map text position to screen coordinates
        RECT rect = { info.position, 0, info.position + 2, 20 };
        HBRUSH brush = CreateSolidBrush(info.color);
        FillRect(hdc, &rect, brush);
        DeleteObject(brush);
    }
}
