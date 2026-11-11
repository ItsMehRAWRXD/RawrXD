#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include <cmath>
#include <cstring>
#include <fstream>

static bool gOwn = false;
static int gTerrain = 0, gBaseSet = 0, gHaveHit = 0, gN = 0, gAt = 0;
static float gMeshY = 0, gBaseY = 0, gHitX = 0, gHitZ = 0;
struct Op { int kind, id; float b[5], a[5]; char bn[16], an[16]; };
static Op gOp[24];
void studioOwn(bool on) { gOwn = on; }
bool studioOwnsUndo() { return gOwn; }
void studioNoteMesh(int n) { gTerrain = n; }
int studioTerrainVerts() { return gTerrain; }
float studioMeshY() { return gMeshY; }
float studioBaseY() { return gBaseY; }
static void applyXform(const Op& o, bool after) {
    EditorEnt* e = editorFind(o.id); if (!e) return;
    const float* s = after ? o.a : o.b;
    e->x = s[0]; e->y = s[1]; e->z = s[2]; e->yaw = s[3]; e->scale = s[4];
}
static void applyName(const Op& o, bool after) {
    EditorEnt* e = editorFind(o.id); if (!e) return;
    std::memcpy(e->name, after ? o.an : o.bn, 16);
}
static void push(Op o) { gN = gAt; gOp[gAt++] = o; gN = gAt; editorRevSlot()++; }
bool studioCommandXform(int id, float x, float y, float z, float yaw, float scale) {
    EditorEnt* e = editorFind(id); if (!e || gAt >= 24) return false;
    Op o{}; o.kind = 1; o.id = id;
    o.b[0]=e->x; o.b[1]=e->y; o.b[2]=e->z; o.b[3]=e->yaw; o.b[4]=e->scale;
    o.a[0]=x; o.a[1]=y; o.a[2]=z; o.a[3]=yaw; o.a[4]=scale;
    push(o); applyXform(gOp[gAt - 1], true); return true;
}
bool studioRename(int id, const char* name) {
    EditorEnt* e = editorFind(id); if (!e || !name || gAt >= 24) return false;
    Op o{}; o.kind = 3; o.id = id; std::memcpy(o.bn, e->name, 16);
    for (int i = 0; i < 15 && name[i]; ++i) o.an[i] = name[i];
    push(o); applyName(gOp[gAt - 1], true); return true;
}
bool studioSculpt(float x, float z, float radius, float dy) {
    if (gAt >= 24) return false;
    Op o{}; o.kind = 2; o.a[0]=x; o.a[1]=z; o.a[2]=radius; o.a[3]=dy;
    if (!gHaveHit) { gHitX = x; gHitZ = z; gHaveHit = 1; }
    o.a[4] = studioBrush().falloff > 0.0f ? studioBrush().falloff : 2.0f;
    o.b[1] = static_cast<float>(studioBrush().mode);
    push(o); return true;
}
static void restore(const Op& o, bool after) {
    if (o.kind == 1) applyXform(o, after); else if (o.kind == 3) applyName(o, after);
    else if (o.kind == 4) { EditorEnt* e = editorFind(o.id); if (e) e->parent = static_cast<int>(after ? o.a[0] : o.b[0]); }
}
bool studioUndo() { if (gAt <= 0) return false; restore(gOp[--gAt], false); editorRevSlot()++; return true; }
bool studioRedo() { if (gAt >= gN) return false; restore(gOp[gAt++], true); editorRevSlot()++; return true; }
void studioApplyStamps(std::vector<Vertex>& v) {
    float best = 1.0e9f, y = 0, base = 0; bool found = false;
    for (Vertex& vert : v) {
        if (vert.uv[1] > 1.5f) continue;
        float lift = 0;
        for (int i = 0; i < gAt; ++i) if (gOp[i].kind == 2) {
            float dx = vert.pos[0] - gOp[i].a[0], dz = vert.pos[2] - gOp[i].a[1];
            float r = gOp[i].a[2], d = std::sqrt(dx * dx + dz * dz);
            if (r > 1.0f && d < r) {
                float t = 1.0f - d / r, fall = gOp[i].a[4] > 0.0f ? gOp[i].a[4] : 2.0f;
                float w = std::pow(t, fall); int mode = static_cast<int>(gOp[i].b[1]);
                if (mode == 2) lift *= (1.0f - w * 0.5f);
                else if (mode == 3) lift += (gOp[i].a[3] - (vert.pos[1] + lift)) * w;
                else lift += gOp[i].a[3] * w;
            }
        }
        vert.pos[1] += lift;
        if (!gHaveHit) continue;
        float d = (vert.pos[0] - gHitX) * (vert.pos[0] - gHitX) + (vert.pos[2] - gHitZ) * (vert.pos[2] - gHitZ);
        if (d < best) { best = d; y = vert.pos[1]; base = y - lift; found = true; }
    }
    if (found) { gMeshY = y; if (!gBaseSet) { gBaseY = base; gBaseSet = 1; } }
}
int studioStampCount() { int n = 0; for (int i = 0; i < gAt; ++i) if (gOp[i].kind == 2) ++n; return n; }
bool studioStampAt(int nth, float& x, float& z, float& r, float& dy, float& fall) {
    int n = 0;
    for (int i = 0; i < gAt; ++i) if (gOp[i].kind == 2 && n++ == nth) {
        x = gOp[i].a[0]; z = gOp[i].a[1]; r = gOp[i].a[2]; dy = gOp[i].a[3]; fall = gOp[i].a[4]; return true;
    }
    return false;
}
bool studioParent(int child, int parent) {
    EditorEnt* e = editorFind(child); if (!e || child == parent || gAt >= 24) return false;
    if (parent && !editorFind(parent)) return false;
    for (int p = parent, n = 0; p && n < 8; ++n) { if (p == child) return false; EditorEnt* u = editorFind(p); p = u ? u->parent : 0; }
    Op o{}; o.kind = 4; o.id = child; o.b[0] = static_cast<float>(e->parent); o.a[0] = static_cast<float>(parent);
    push(o); e->parent = parent; return true;
}
