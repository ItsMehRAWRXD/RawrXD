#include "terrain_studio.hpp"
#include <cstdio>
#include <cstring>

struct Prop { int id; float x, y, z, yaw, scale; char name[16]; };
static Prop gProp[2];
static int gSel = 0;
static int gPlay = 0;
struct XUndo { int id; int seq; float b[5]; float a[5]; };
static XUndo gX[8];
static int gXAt = 0;
static int gXN = 0;

static Prop* findProp(int id) {
    for (int i = 0; i < 2; ++i) if (gProp[i].id == id) return &gProp[i];
    return nullptr;
}
void studioResetProps() {
    gProp[0] = {1, 4, 0, 4, 0, 1, {}}; std::memcpy(gProp[0].name, "Marker", 7);
    gProp[1] = {2, -6, 0, 8, 0, 1, {}}; std::memcpy(gProp[1].name, "Spawn", 6);
    gSel = 1; gPlay = 0; gXAt = gXN = 0;
}
int studioSelect(int id) { if (!findProp(id)) return 0; gSel = id; return id; }
int studioSelected() { return gSel; }
bool studioObject(int id, float& x, float& y, float& z, float& yaw, float& scale) {
    Prop* p = findProp(id);
    if (!p) return false;
    x = p->x; y = p->y; z = p->z; yaw = p->yaw; scale = p->scale;
    return true;
}
bool studioTransform(int id, float x, float y, float z, float yaw, float scale) {
    Prop* p = findProp(id);
    if (!p || gXAt >= 8) return false;
    gXN = gXAt;
    XUndo& u = gX[gXAt++];
    u = {id, ++gStudioClock, {p->x, p->y, p->z, p->yaw, p->scale}, {x, y, z, yaw, scale}};
    gXN = gXAt;
    gXformSeq = u.seq;
    p->x = x; p->y = y; p->z = z; p->yaw = yaw; p->scale = scale;
    return true;
}
bool studioUndoXform() {
    if (gXAt <= 0) return false;
    XUndo u = gX[--gXAt];
    Prop* p = findProp(u.id);
    if (!p) return false;
    p->x = u.b[0]; p->y = u.b[1]; p->z = u.b[2]; p->yaw = u.b[3]; p->scale = u.b[4];
    gXformSeq = gXAt > 0 ? gX[gXAt - 1].seq : 0;
    return true;
}
void studioPlay(bool on) { gPlay = on ? 1 : 0; }
bool studioPlaying() { return gPlay != 0; }
bool studioAsk(const char* text) {
    if (!text || !std::strstr(text, "mountain")) return false;
    studioSetBrush(0, 8.0f, 7.0f, 2.0f);
    return studioStroke(8.0f, 12.0f) > 0;
}
bool studioSave(const char* path) {
    FILE* f = std::fopen(path, "wb");
    if (!f) return false;
    int n = studioResolution();
    std::fwrite("STU1", 1, 4, f);
    std::fwrite(&n, 4, 1, f);
    std::fwrite(studioHeights(), sizeof(float), static_cast<size_t>(n * n), f);
    std::fwrite(gProp, sizeof(Prop), 2, f);
    std::fclose(f);
    return true;
}
bool studioLoad(const char* path) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    char magic[4]; int n = 0;
    bool ok = std::fread(magic, 1, 4, f) == 4 && std::memcmp(magic, "STU1", 4) == 0 && std::fread(&n, 4, 1, f) == 1 && n == studioResolution();
    if (ok) ok = std::fread(studioHeights(), sizeof(float), static_cast<size_t>(n * n), f) == static_cast<size_t>(n * n);
    if (ok) ok = std::fread(gProp, sizeof(Prop), 2, f) == 2;
    std::fclose(f);
    return ok;
}
