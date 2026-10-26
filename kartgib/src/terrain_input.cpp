#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "win32_window.hpp"

void studioPointer(Win32Window& window, const float view[16], const float proj[16],
    int x, int y, bool clicked, bool released) {
    (void)view; (void)proj; (void)released;
    if (!studioBrushOn() || editorPlaying()) return;
    if (clicked) studioBrush(window, x, y);
}
