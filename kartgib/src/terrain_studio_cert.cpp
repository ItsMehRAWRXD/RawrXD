#include "terrain_studio.hpp"
#include <cmath>
#include <cstdio>

static int gFail = 0;
static void check(bool ok, const char* name) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++gFail;
}
int main() {
    const char* path = "F:/rawrxd/kartgib/evidence/terrain_studio.stu1";
    check(studioCreate("Valley"), "create");
    studioGenerateSmooth();
    float smooth = studioHeight(0, 0);
    studioSetBrush(0, 6, 8, 2);
    int m0 = studioStroke(-20, -10);
    int m1 = studioStroke(0, 16);
    int m2 = studioStroke(24, -8);
    check(m0 > 0 && m1 > 0 && m2 > 0, "three_mountains");
    check(m0 < studioResolution() * studioResolution(), "partial_update");
    float peak = studioHeight(-20, -10);
    check(peak > smooth + 1.0f, "raised");
    studioSetBrush(1, 6, 6, 2);
    check(studioStroke(0, 0) > 0, "valley");
    float dug = studioHeight(0, 0);
    check(terrainUndo(), "undo_valley");
    check(studioHeight(0, 0) > dug + 0.5f, "undo_restored");
    check(terrainRedo(), "redo_valley");
    check(std::fabs(studioHeight(0, 0) - dug) < 0.05f, "redo_matches");
    check(studioSave(path) && studioCreate("Blank") && studioLoad(path), "save_reload");
    check(std::fabs(studioHeight(-20, -10) - peak) < 0.05f, "peak_reloaded");
    float ox, oy, oz, oyaw, oscale;
    check(studioSelect(1) == 1 && studioObject(1, ox, oy, oz, oyaw, oscale), "select");
    check(studioTransform(1, 3, 4, 5, 0.2f, 1.5f), "transform");
    check(terrainUndo(), "undo_transform");
    float x, y, z, yaw, scale;
    studioObject(1, x, y, z, yaw, scale);
    check(std::fabs(x - ox) < 0.01f && std::fabs(scale - oscale) < 0.01f, "object_restored");
    studioPlay(true);
    check(studioPlaying() && std::fabs(studioHeight(-20, -10) - peak) < 0.05f, "play_collider");
    float before = studioHeight(8, 12);
    check(studioAsk("add a mountain beside the valley"), "sunshine");
    check(studioHeight(8, 12) > before + 1.0f, "sunshine_height");
    check(terrainUndo() && studioHeight(8, 12) < before + 1.0f, "sunshine_undo");
    float view[16], proj[16];
    studioCamera(view, proj, 1280, 720);
    int px = 0, py = 0;
    float aim = studioHeight(10, 10);
    check(studioProject(view, proj, 10, aim + 2, 10, 1280, 720, px, py), "project");
    studioSetBrush(0, 12, 5, 2);
    check(studioStrokeScreen(view, proj, 1280, 720, px, py) > 0, "mouse_ray");
    check(studioHeight(10, 10) > aim + 0.5f, "mouse_raised");
    std::printf("FAILS %d\n", gFail);
    std::printf("LIVE_VIEWPORT=NOT_RUN\nINSPECTOR_PANEL=NOT_RUN\nPROMOTE=0\n");
    return gFail == 0 ? 0 : 1;
}
