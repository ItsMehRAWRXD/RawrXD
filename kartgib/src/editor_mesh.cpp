#include "editor_api.hpp"
#include <cmath>
#include <cstring>

static void box(std::vector<Vertex>& v, std::vector<uint32_t>& idx, float x, float y, float z, float yaw, float s, float uv) {
    float c = std::cos(yaw), sn = std::sin(yaw), h = 1.5f * s;
    uint32_t b = static_cast<uint32_t>(v.size());
    const float p[8][3] = {{-h,-h,-h},{h,-h,-h},{h,h,-h},{-h,h,-h},{-h,-h,h},{h,-h,h},{h,h,h},{-h,h,h}};
    for (int i = 0; i < 8; ++i) {
        Vertex t{};
        t.pos[0] = x + p[i][0] * c - p[i][2] * sn; t.pos[1] = y + p[i][1]; t.pos[2] = z + p[i][0] * sn + p[i][2] * c;
        t.normal[1] = 1; t.uv[1] = uv; v.push_back(t);
    }
    const int f[] = {0,2,1,0,3,2,4,5,6,4,6,7,0,1,5,0,5,4,1,2,6,1,6,5,3,7,6,3,6,2,0,4,7,0,7,3,
        0,1,2,0,2,3,4,6,5,4,7,6,0,5,1,0,4,5,1,6,2,1,5,6,3,6,7,3,2,6,0,7,4,0,3,7};
    for (int i : f) idx.push_back(b + i);
}
static void glyph(std::vector<Vertex>& v, std::vector<uint32_t>& idx, float x, float y, int bits) {
    for (int row = 0; row < 5; ++row) for (int col = 0; col < 3; ++col) {
        if (((bits >> (row * 3 + col)) & 1) == 0) continue;
        float px = x + col * 0.018f, py = y - row * 0.028f;
        uint32_t b = static_cast<uint32_t>(v.size());
        float q[4][2] = {{px, py}, {px + 0.016f, py}, {px + 0.016f, py - 0.024f}, {px, py - 0.024f}};
        for (int i = 0; i < 4; ++i) { Vertex t{}; t.pos[0] = q[i][0]; t.pos[1] = q[i][1]; t.uv[1] = 10; v.push_back(t); }
        const int fan[] = {0, 1, 2, 0, 2, 3};
        for (int i : fan) idx.push_back(b + i);
    }
}
static const int kFont[11] = {0x15D6B5, 0x1C421F, 0x1F421F, 0x1F47A5, 0x1F0BE2, 0x0F47A1, 0x104104, 0x1F47BF, 0x1F47A1, 0x0E5B17, 0x0};
static void drawNum(std::vector<Vertex>& v, std::vector<uint32_t>& idx, float x, float y, int value) {
    char text[8]; int n = 0; int neg = value < 0; if (neg) value = -value;
    if (value == 0) text[n++] = '0';
    while (value > 0 && n < 6) { text[n++] = static_cast<char>('0' + value % 10); value /= 10; }
    if (neg) text[n++] = '-';
    for (int i = n - 1; i >= 0; --i) {
        int glyphId = text[i] == '-' ? 10 : text[i] - '0';
        glyph(v, idx, x, y, kFont[glyphId]);
        x += 0.07f;
    }
}
void editorAppend(std::vector<Vertex>& v, std::vector<uint32_t>& idx) {
    for (int i = 0; i < editorCount(); ++i) {
        const EditorEnt& e = *editorAt(i);
        box(v, idx, e.x, e.y, e.z, e.yaw, e.scale, 3.0f);
    }
    const EditorEnt* sel = nullptr;
    for (int i = 0; i < editorCount(); ++i) if (editorAt(i)->id == editorSelected()) sel = editorAt(i);
    if (sel && !editorPlaying()) {
        box(v, idx, sel->x, sel->y, sel->z, sel->yaw, sel->scale + 0.55f, 5.0f);
        int axes = editorGizmoMode() == 0 ? 3 : 8;
        for (int a = 0; a < axes; ++a) {
            float dx, dy, dz; editorAxis(editorGizmoMode() == 0 ? a : 0, dx, dy, dz);
            float ang = a * 0.785398f;
            if (editorGizmoMode() == 1) { dx = std::cos(sel->yaw + ang); dy = 0; dz = std::sin(sel->yaw + ang); }
            float dist = editorGizmoMode() == 2 ? 5.0f : 6.0f;
            float uv = editorGizmoMode() == 1 ? 9.0f : (a == 1 ? 8.0f : a == 2 ? 9.0f : 7.0f);
            box(v, idx, sel->x + dx * dist, sel->y + dy * dist, sel->z + dz * dist, 0, 0.45f, uv);
        }
    }
    int shown = sel ? static_cast<int>(std::round(sel->x * 10.0f)) : 0;
    drawNum(v, idx, -0.92f, 0.92f, sel ? sel->id : 0);
    drawNum(v, idx, -0.55f, 0.92f, shown);
    drawNum(v, idx, -0.15f, 0.92f, sel ? static_cast<int>(std::round(sel->yaw * 180.0f / 3.14159265f)) : 0);
    drawNum(v, idx, 0.28f, 0.92f, sel ? static_cast<int>(std::round(sel->scale * 10.0f)) : 0);
}
