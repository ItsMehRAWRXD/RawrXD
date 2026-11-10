#include "terrain_studio.hpp"
#include <cmath>
#include <cstring>
static const int kN = 33;
static const float kWorld = 128.0f;
static float gH[kN * kN];
float* studioHeights() { return gH; }
static char gName[32];
static StudioBrush gBrush;
static int gBrushOn = 0;
static int gDirty = 0;
static int gOpen = 0;
struct Sample { int i; float before; float after; };
static Sample gCur[96];
static int gCurN = 0;
struct Undo { int n; int seq; Sample s[96]; };
static Undo gUndo[12];
static int gAt = 0;
static int gUndoN = 0;
static int indexAt(float x, float z, int& i, int& j) {
    float u = (x + kWorld * 0.5f) / kWorld;
    float v = (z + kWorld * 0.5f) / kWorld;
    if (u < 0.0f || v < 0.0f || u > 1.0f || v > 1.0f) return 0;
    i = static_cast<int>(u * (kN - 1) + 0.5f);
    j = static_cast<int>(v * (kN - 1) + 0.5f);
    return 1;
}
static void worldAt(int i, int j, float& x, float& z) {
    float step = kWorld / static_cast<float>(kN - 1);
    x = -kWorld * 0.5f + static_cast<float>(i) * step;
    z = -kWorld * 0.5f + static_cast<float>(j) * step;
}
bool studioCreate(const char* name) {
    std::memset(gH, 0, sizeof(gH));
    std::memset(gName, 0, sizeof(gName));
    if (name) for (int i = 0; i < 31 && name[i]; ++i) gName[i] = name[i];
    gBrush = {};
    gDirty = gOpen = gCurN = gAt = gUndoN = 0;
    gStudioClock = 1; gHeightSeq = 0; gXformSeq = 0;
    studioResetProps();
    return true;
}
const char* studioName() { return gName; }
void studioGenerateSmooth() {
    for (int j = 0; j < kN; ++j) for (int i = 0; i < kN; ++i) {
        gH[j * kN + i] = 1.5f * std::sin(i * 0.35f) * std::cos(j * 0.28f);
    }
}
void studioSetBrush(int mode, float radius, float strength, float falloff) {
    gBrush.mode = mode; gBrush.radius = radius; gBrush.strength = strength; gBrush.falloff = falloff;
}
const StudioBrush& studioBrush() { return gBrush; }
void studioBrushEnable(bool on) { gBrushOn = on ? 1 : 0; }
bool studioBrushOn() { return gBrushOn != 0; }
void studioBegin() { gOpen = 1; gCurN = 0; }
void studioEnd() {
    if (!gOpen || gCurN == 0 || gAt >= 12) { gOpen = 0; gCurN = 0; return; }
    Undo& slot = gUndo[gAt];
    slot.n = gCurN;
    for (int i = 0; i < gCurN; ++i) slot.s[i] = gCur[i];
    slot.seq = gHeightSeq = ++gStudioClock;
    gUndoN = ++gAt;
    gOpen = 0; gCurN = 0;
}
int studioStamp(float x, float z) {
    if (!gOpen) studioBegin();
    int i0 = 0, j0 = 0;
    if (!indexAt(x, z, i0, j0)) return 0;
    float step = kWorld / static_cast<float>(kN - 1);
    int rad = static_cast<int>(gBrush.radius / step) + 1;
    int touched = 0;
    float sign = gBrush.mode == 1 ? -1.0f : 1.0f;
    for (int j = j0 - rad; j <= j0 + rad; ++j) for (int i = i0 - rad; i <= i0 + rad; ++i) {
        if (i < 0 || j < 0 || i >= kN || j >= kN || gCurN >= 96) continue;
        float wx, wz; worldAt(i, j, wx, wz);
        float d = std::hypot(wx - x, wz - z);
        if (d > gBrush.radius) continue;
        float t = d / gBrush.radius;
        float w = std::pow(1.0f - t, gBrush.falloff);
        int id = j * kN + i;
        gCur[gCurN++] = {id, gH[id], gH[id] + sign * gBrush.strength * w};
        gH[id] += sign * gBrush.strength * w;
        ++touched;
    }
    gDirty = touched;
    return touched;
}
int studioStroke(float x, float z) { studioBegin(); int n = studioStamp(x, z); studioEnd(); return n; }
bool terrainUndo() {
    if (gXformSeq > gHeightSeq && studioUndoXform()) return true;
    if (gAt <= 0) return false;
    Undo u = gUndo[--gAt];
    for (int i = 0; i < u.n; ++i) gH[u.s[i].i] = u.s[i].before;
    gHeightSeq = gAt > 0 ? gUndo[gAt - 1].seq : 0;
    return true;
}
bool terrainRedo() {
    if (gAt >= gUndoN) return false;
    Undo u = gUndo[gAt++];
    for (int i = 0; i < u.n; ++i) gH[u.s[i].i] = u.s[i].after;
    gHeightSeq = u.seq;
    return true;
}
int studioDirtyVerts() { return gDirty; }
