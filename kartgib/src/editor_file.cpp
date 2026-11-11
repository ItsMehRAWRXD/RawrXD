#include "editor_api.hpp"
#include <fstream>
#include <cstring>
EditorEnt* editorSlots();
int& editorSlotCount();
int& editorRevSlot();
int& editorSelSlot();
EditorEnt* editorFind(int id);

bool editorDelete(int id) {
    int& n = editorSlotCount();
    int found = -1;
    for (int i = 0; i < n; ++i) if (editorSlots()[i].id == id) found = i;
    if (found < 0) return false;
    for (int i = found; i < n - 1; ++i) editorSlots()[i] = editorSlots()[i + 1];
    --n;
    if (editorSelSlot() == id) editorSelSlot() = -1;
    editorRevSlot()++;
    return true;
}
void editorDuplicate(int id) {
    EditorEnt* e = editorFind(id);
    int& n = editorSlotCount();
    if (!e || n >= 8) return;
    int nid = 1;
    for (int i = 0; i < n; ++i) if (editorSlots()[i].id >= nid) nid = editorSlots()[i].id + 1;
    editorSlots()[n] = *e;
    editorSlots()[n].id = nid;
    editorSlots()[n].parent = id;
    std::memset(editorSlots()[n].name, 0, 16);
    std::memcpy(editorSlots()[n].name, "Copy", 5);
    ++n;
    editorRevSlot()++;
}
void editorRename(int id, const char* name) {
    EditorEnt* e = editorFind(id);
    if (!e || !name) return;
    std::memset(e->name, 0, 16);
    for (int i = 0; i < 15 && name[i]; ++i) e->name[i] = name[i];
}
static EditorEnt gSnap[8];
static int gSnapN = 0;
static int gPlay = 0;
void editorResetPlay() { gPlay = 0; gSnapN = 0; }
void editorPlayToggle() {
    if (!gPlay) {
        gSnapN = editorSlotCount();
        for (int i = 0; i < gSnapN; ++i) gSnap[i] = editorSlots()[i];
        gPlay = 1;
        return;
    }
    editorSlotCount() = gSnapN;
    for (int i = 0; i < gSnapN; ++i) editorSlots()[i] = gSnap[i];
    gPlay = 0;
    editorRevSlot()++;
}
void editorPlayStep() {
    if (!gPlay || editorSlotCount() < 1) return;
    editorSlots()[0].z += 4.0f;
    editorRevSlot()++;
}
bool editorPlaying() { return gPlay != 0; }
bool editorParent(int child, int parent) { return studioOwnsUndo() && studioParent(child, parent); }
bool editorSaveAtomic(const char* path) {
    std::string tmp = std::string(path) + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) return false;
    out << "KARTGIB_SCENE 1\n" << editorSlotCount() << "\n";
    for (int i = 0; i < editorSlotCount(); ++i) {
        const EditorEnt& e = editorSlots()[i];
        out << e.id << " " << e.parent << " " << e.name << " " << e.x << " " << e.y << " " << e.z
            << " " << e.yaw << " " << e.scale << "\n";
    }
    out.close();
    return MoveFileExA(tmp.c_str(), path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}
bool editorLoad(const char* path) {
    std::ifstream in(path);
    char magic[32] = {};
    int ver = 0, n = 0;
    if (!(in >> magic >> ver >> n) || std::strcmp(magic, "KARTGIB_SCENE") != 0 || ver != 1 || n < 1 || n > 8) return false;
    EditorEnt loaded[8];
    for (int i = 0; i < n; ++i) {
        if (!(in >> loaded[i].id >> loaded[i].parent >> loaded[i].name >> loaded[i].x >> loaded[i].y
            >> loaded[i].z >> loaded[i].yaw >> loaded[i].scale)) return false;
    }
    editorSlotCount() = n;
    for (int i = 0; i < n; ++i) editorSlots()[i] = loaded[i];
    editorClearJournal();
    editorRevSlot()++;
    return true;
}
