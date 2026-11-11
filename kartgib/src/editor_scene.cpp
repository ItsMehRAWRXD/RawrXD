#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include <cstring>

static EditorEnt gEnt[8];
static int gN = 0;
static int gRev = 1;
static int gSel = -1;
static int gMode = 0;
static int gLocal = 0;
static float gBootX = 16, gBootYaw = 0, gBootScale = 1, gBoot2 = 34;
struct Hist { int id; float bx, by, bz, byaw, bs, ax, ay, az, ayaw, as; };
static Hist gHist[24];
static int gHistN = 0;
static int gAt = 0;
static int gKeys[16];
static int gKeyN = 0;
static bool gShow = false;
static bool gDone = false;

static EditorEnt* findEnt(int id) {
    for (int i = 0; i < gN; ++i) if (gEnt[i].id == id) return &gEnt[i];
    return nullptr;
}
void editorBoot() {
    gN = 2; gRev = 1; gSel = -1; gMode = 0; gLocal = 0; gHistN = gAt = gKeyN = 0; gDone = false;
    editorResetPlay();
    gEnt[0] = {1, 0, 16, 18, 24, 0, 1, {}}; std::memcpy(gEnt[0].name, "BoxA", 5);
    gEnt[1] = {2, 0, 34, 14, 36, 0, 1.3f, {}}; std::memcpy(gEnt[1].name, "BoxB", 5);
    gBootX = 16; gBootYaw = 0; gBootScale = 1; gBoot2 = 34;
    studioCreate("Valley");
    studioGenerateSmooth();
}
void editorSetShow(bool show) { gShow = show; }
bool editorShowOnly() { return gShow; }
bool editorSessionDone() { return gDone; }
void editorMarkDone() { gDone = true; }
int editorCount() { return gN; }
const EditorEnt* editorAt(int i) { return (i >= 0 && i < gN) ? &gEnt[i] : nullptr; }
int editorRevision() { return gRev; }
int editorSelected() { return gSel; }
void editorSelect(int id) { gSel = id; gRev++; }
int editorGizmoMode() { return gMode; }
void editorSetMode(int mode) { gMode = mode; }
bool editorLocal() { return gLocal != 0; }
void editorToggleLocal() { gLocal = gLocal ? 0 : 1; }
int editorHistAt() { return gAt; }
void editorBootPose(float& x, float& yaw, float& scale, float& x2) { x = gBootX; yaw = gBootYaw; scale = gBootScale; x2 = gBoot2; }
void editorNoteKey(int vk) { if (gKeyN < 16) gKeys[gKeyN++] = vk; }
bool editorTakeKey(int& vk) { if (gKeyN == 0) return false; vk = gKeys[0]; std::memmove(gKeys, gKeys + 1, sizeof(int) * (--gKeyN)); return true; }
bool editorCommand(int id, float x, float y, float z, float yaw, float scale) {
    if (studioOwnsUndo()) return studioCommandXform(id, x, y, z, yaw, scale);
    EditorEnt* e = findEnt(id);
    if (!e || gAt >= 24) return false;
    gHistN = gAt;
    Hist& h = gHist[gAt++];
    h = {id, e->x, e->y, e->z, e->yaw, e->scale, x, y, z, yaw, scale};
    gHistN = gAt;
    e->x = x; e->y = y; e->z = z; e->yaw = yaw; e->scale = scale;
    gRev++;
    return true;
}
bool editorUndo() {
    if (studioOwnsUndo()) return studioUndo();
    if (gAt <= 0) return false;
    Hist h = gHist[--gAt];
    EditorEnt* e = findEnt(h.id);
    if (!e) return false;
    e->x = h.bx; e->y = h.by; e->z = h.bz; e->yaw = h.byaw; e->scale = h.bs;
    gRev++;
    return true;
}
bool editorRedo() {
    if (studioOwnsUndo()) return studioRedo();
    if (gAt >= gHistN) return false;
    Hist h = gHist[gAt++];
    EditorEnt* e = findEnt(h.id);
    if (!e) return false;
    e->x = h.ax; e->y = h.ay; e->z = h.az; e->yaw = h.ayaw; e->scale = h.as;
    gRev++;
    return true;
}
EditorEnt* editorSlots() { return gEnt; }
int& editorSlotCount() { return gN; }
int& editorRevSlot() { return gRev; }
int& editorSelSlot() { return gSel; }
EditorEnt* editorFind(int id) { return findEnt(id); }
void editorClearJournal() { gHistN = gAt = 0; }
