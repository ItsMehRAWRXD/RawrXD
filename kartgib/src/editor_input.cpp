#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "win32_window.hpp"
#include <cmath>

static int gDrag = -1;
static float gBx, gBy, gBz, gByaw, gBscale;
static float snap(float v, float step) { return std::round(v / step) * step; }
static const EditorEnt* selected() {
    for (int i = 0; i < editorCount(); ++i) if (editorAt(i)->id == editorSelected()) return editorAt(i);
    return nullptr;
}
static int nearest(const float view[16], const float proj[16], int w, int h, int mx, int my, bool handles) {
    const EditorEnt* e = selected();
    int best = -1; float bestD = 1.0e9f; float bestW = 1.0e9f;
    int n = handles ? (editorGizmoMode() == 0 ? 3 : 1) : editorCount();
    for (int i = 0; i < n; ++i) {
        float x, y, z, depth; int px, py;
        if (handles) {
            if (!e) return -1;
            float dx, dy, dz; editorAxis(i, dx, dy, dz);
            float dist = editorGizmoMode() == 2 ? 5.0f : 6.0f;
            x = e->x + dx * dist; y = e->y + dy * dist; z = e->z + dz * dist;
        } else { x = editorAt(i)->x; y = editorAt(i)->y; z = editorAt(i)->z; }
        if (!editorProject(view, proj, x, y, z, w, h, px, py, depth)) continue;
        float d = std::hypot(static_cast<float>(px - mx), static_cast<float>(py - my));
        float limit = handles ? 36.0f : 55.0f;
        if (d < limit && (d < bestD - 4.0f || (std::fabs(d - bestD) <= 4.0f && depth < bestW))) {
            bestD = d; bestW = depth; best = handles ? i : editorAt(i)->id;
        }
    }
    return best;
}
static void commit(const float view[16], const float proj[16], int w, int h, int x0, int y0, int x1, int y1) {
    const EditorEnt* e = selected();
    if (!e || gDrag < 0) return;
    float dx, dy, dz; editorAxis(gDrag, dx, dy, dz);
    int ax, ay, bx, by; float depth;
    editorProject(view, proj, e->x, e->y, e->z, w, h, ax, ay, depth);
    float dist = editorGizmoMode() == 2 ? 5.0f : 6.0f;
    editorProject(view, proj, e->x + dx * dist, e->y + dy * dist, e->z + dz * dist, w, h, bx, by, depth);
    float sx = static_cast<float>(bx - ax), sy = static_cast<float>(by - ay);
    float mx = static_cast<float>(x1 - x0), my = static_cast<float>(y1 - y0);
    float len2 = sx * sx + sy * sy;
    float along = len2 > 1.0f ? (mx * sx + my * sy) / len2 : 0.0f;
    float nx = gBx, ny = gBy, nz = gBz, nyaw = gByaw, ns = gBscale;
    if (editorGizmoMode() == 0) {
        float delta = snap(along * dist, 0.5f);
        nx = gBx + dx * delta; ny = gBy + dy * delta; nz = gBz + dz * delta;
    } else if (editorGizmoMode() == 1) {
        nyaw = gByaw + snap(mx * 0.015f, 15.0f * 3.14159265f / 180.0f);
    } else {
        ns = snap(gBscale + mx * 0.008f, 0.1f);
        if (ns < 0.2f) ns = 0.2f;
    }
    if (nx != gBx || ny != gBy || nz != gBz || nyaw != gByaw || ns != gBscale)
        editorCommand(e->id, nx, ny, nz, nyaw, ns);
    gDrag = -1;
}
void editorHandleInput(Win32Window& window) {
    bool ctrl = false, undo = false, redo = false, save = false;
    int vk = 0;
    while (editorTakeKey(vk)) {
        if (vk == VK_CONTROL) ctrl = true;
        else if (vk == 'Z') undo = true;
        else if (vk == 'Y') redo = true;
        else if (vk == 'S' && ctrl) save = true;
        else if (vk == 'T') editorSetMode(0);
        else if (vk == 'R') editorSetMode(1);
        else if (vk == 'S') editorSetMode(2);
        else if (vk == 'B') { editorSetMode(3); studioBrushEnable(!studioBrushOn()); }
        else if (vk == 'L') editorToggleLocal();
        else if (vk == 'P') editorPlayToggle();
    }
    if (ctrl && undo) editorUndo();
    if (ctrl && redo) editorRedo();
    if (save) editorSaveAtomic("F:/rawrxd/kartgib/evidence/kartgib_editor_scene.txt");
    int x, y, x0, y0; bool clicked = false, released = false;
    window.consumePointer(x, y, x0, y0, clicked, released);
    float view[16], proj[16];
    editorCamera(view, proj, window.getWidth(), window.getHeight());
    if (studioBrushOn()) studioPointer(window, view, proj, x, y, clicked, released);
    else if (clicked && !editorPlaying()) {
        if (editorGizmoMode() == 3) { studioBrush(window, x0, y0); gDrag = -1; }
        int handle = editorGizmoMode() == 3 ? -1 : nearest(view, proj, window.getWidth(), window.getHeight(), x0, y0, true);
        int ent = nearest(view, proj, window.getWidth(), window.getHeight(), x0, y0, false);
        if (handle >= 0 && editorSelected() > 0) {
            const EditorEnt* e = selected();
            gDrag = handle; gBx = e->x; gBy = e->y; gBz = e->z; gByaw = e->yaw; gBscale = e->scale;
        } else gDrag = -1;
        if (handle < 0 && editorGizmoMode() != 3) editorSelect(ent);
    }
    if (released && gDrag >= 0) commit(view, proj, window.getWidth(), window.getHeight(), x0, y0, x, y);
}
