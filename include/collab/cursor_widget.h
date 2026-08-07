
#ifndef CURSOR_WIDGET_H
#define CURSOR_WIDGET_H

#include <string>
#include <map>
#include <windows.h>

// Presence: cursor position, user name, avatar color (Win32 native, no Qt)
class CursorWidget
{
public:
    explicit CursorWidget(void* parentHandle = nullptr);

    struct CursorInfo {
        int position;
        std::string userName;
        COLORREF color;
    };

    // Add or update a cursor
    void updateCursor(const std::string &userId, const CursorInfo &info);

    // Remove a cursor
    void removeCursor(const std::string &userId);

    // Paint cursors into the given HDC (call from WM_PAINT of parent)
    void paint(HDC hdc);

    void setHandle(void* handle) { m_handle = handle; }

private:
    std::map<std::string, CursorInfo> m_cursors;
    void* m_handle;
};

#endif // CURSOR_WIDGET_H

