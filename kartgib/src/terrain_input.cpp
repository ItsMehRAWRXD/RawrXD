#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "win32_window.hpp"

void studioPointer(Win32Window& window, const float view[16], const float proj[16],
    int x, int y, bool clicked, bool released) {
    (void)view; (void)proj;
    studioMoveCursor(window.getHandle(), x, y);
    if (!studioBrushOn() || editorPlaying()) return;
    if (released) studioBrush(window, x, y);
    (void)clicked;
}
