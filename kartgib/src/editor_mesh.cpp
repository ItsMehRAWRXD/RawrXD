#include "editor_api.hpp"
#include <cmath>

static void box(std::vector<Vertex>& v, std::vector<uint32_t>& idx, float x, float y, float z, float yaw, float s, float uv) {
    float c = std::cos(yaw), sn = std::sin(yaw), h = 1.5f * s;
    const float p[8][3] = {{-h,-h,-h},{h,-h,-h},{h,h,-h},{-h,h,-h},{-h,-h,h},{h,-h,h},{h,h,h},{-h,h,h}};
    const int q[6][4] = {{0,1,2,3},{4,5,6,7},{0,4,5,1},{1,5,6,2},{3,2,6,7},{0,3,7,4}};
    const float nrm[6][3] = {{0,0,-1},{0,0,1},{0,-1,0},{1,0,0},{0,1,0},{-1,0,0}};
    for (int f = 0; f < 6; ++f) {
        uint32_t b = static_cast<uint32_t>(v.size());
        float nx = nrm[f][0] * c - nrm[f][2] * sn, nz = nrm[f][0] * sn + nrm[f][2] * c;
        for (int i = 0; i < 4; ++i) {
            const float* a = p[q[f][i]];
            Vertex t{};
            t.pos[0] = x + a[0] * c - a[2] * sn; t.pos[1] = y + a[1]; t.pos[2] = z + a[0] * sn + a[2] * c;
            t.normal[0] = nx; t.normal[1] = nrm[f][1]; t.normal[2] = nz; t.uv[1] = uv;
            v.push_back(t);
        }
        const int fan[] = {0, 1, 2, 0, 2, 3};
        for (int i : fan) idx.push_back(b + i);
    }
}
void editorAppend(std::vector<Vertex>& v, std::vector<uint32_t>& idx) {
    for (int i = 0; i < editorCount(); ++i) {
        const EditorEnt& e = *editorAt(i);
        box(v, idx, e.x, e.y, e.z, e.yaw, e.scale, 3.0f);
    }
    const EditorEnt* sel = nullptr;
    for (int i = 0; i < editorCount(); ++i) if (editorAt(i)->id == editorSelected()) sel = editorAt(i);
    if (!sel || editorPlaying()) return;
    float reach = 1.5f * sel->scale + 0.35f, c = std::cos(sel->yaw), sn = std::sin(sel->yaw);
    const float corner[4][2] = {{-reach, -reach}, {reach, -reach}, {reach, reach}, {-reach, reach}};
    for (int i = 0; i < 4; ++i) {
        float x = sel->x + corner[i][0] * c - corner[i][1] * sn;
        float z = sel->z + corner[i][0] * sn + corner[i][1] * c;
        box(v, idx, x, sel->y + reach, z, 0, 0.12f, 5.0f);
    }
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
