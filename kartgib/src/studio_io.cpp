#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <filesystem>
int studioStampCount();
bool studioStampAt(int nth, float& x, float& z, float& r, float& dy, float& fall);
bool studioSaveStamps(const char* path) {
    std::ofstream o(path); if (!o) return false;
    int n = studioStampCount(); o << n << "\n";
    for (int i = 0; i < n; ++i) { float x, z, r, dy, fall; studioStampAt(i, x, z, r, dy, fall); o << x << " " << z << " " << r << " " << dy << " " << fall << "\n"; }
    return true;
}
bool studioLoadStamps(const char* path) {
    std::ifstream in(path); int n = 0; if (!(in >> n)) return false;
    for (int i = 0; i < n; ++i) {
        float x = 0, z = 0, r = 0, dy = 0, fall = 2;
        if (!(in >> x >> z >> r >> dy >> fall)) return false;
        studioSetBrush(dy < 0.0f ? 1 : 0, r, std::fabs(dy), fall);
        if (!studioSculpt(x, z, r, dy)) return false;
    }
    return true;
}

bool studioCreateProject(const char* dir) {
    std::filesystem::create_directories(dir);
    std::ofstream out(std::string(dir) + "/project.txt");
    if (!out) return false;
    out << "name RawrXDStudio\nseed 20261025\nterrain smooth\n";
    return true;
}
bool studioSaveProject(const char* dir) {
    std::filesystem::create_directories(dir);
    return editorSaveAtomic((std::string(dir) + "/scene.txt").c_str()) && studioSaveStamps((std::string(dir) + "/stamps.txt").c_str());
}
bool studioLoadProject(const char* dir) {
    std::string root(dir);
    return editorLoad((root + "/scene.txt").c_str()) && studioLoadStamps((root + "/stamps.txt").c_str());
}
bool sunshineScene(const char* line) {
    char op[32]{};
    if (!line || std::sscanf(line, "%31s", op) != 1) return false;
    if (!std::strcmp(op, "undo")) return editorUndo();
    if (!std::strcmp(op, "redo")) return editorRedo();
    if (!std::strcmp(op, "play")) { editorPlayToggle(); return true; }
    if (!std::strcmp(op, "sculpt")) {
        float x, z, r, dy;
        return std::sscanf(line, "%*s %f %f %f %f", &x, &z, &r, &dy) == 4 && studioSculpt(x, z, r, dy);
    }
    if (!std::strcmp(op, "transform")) {
        int id; float x, y, z, yaw, scale;
        return std::sscanf(line, "%*s %d %f %f %f %f %f", &id, &x, &y, &z, &yaw, &scale) == 6 && editorCommand(id, x, y, z, yaw, scale);
    }
    if (!std::strcmp(op, "parent")) { int child, parent; return std::sscanf(line, "%*s %d %d", &child, &parent) == 2 && editorParent(child, parent); }
    if (!std::strcmp(op, "rename")) {
        int id; char name[16]{};
        return std::sscanf(line, "%*s %d %15s", &id, name) == 2 && studioRename(id, name);
    }
    return false;
}
