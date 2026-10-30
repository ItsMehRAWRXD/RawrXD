#include "editor_api.hpp"
#include "win32_window.hpp"
#include <windows.h>
#include <cmath>
#include <fstream>
#include <string>
#include <vector>
#include <iostream>
#include <cstdio>
void exeSha256(char out[65]);

static bool closeTo(float a, float b) { return std::fabs(a - b) < 1.0e-3f; }
static bool grid(float v, float step) { return std::fabs(v / step - std::round(v / step)) < 1.0e-3f; }
static uint64_t shotHash(const char* name) {
    for (int i = 0; i < editorShotCount(); ++i) if (std::strcmp(editorShotAt(i)->name, name) == 0) return editorShotAt(i)->hash;
    return 0;
}
static int shotTone(const char* name, bool red) {
    for (int i = 0; i < editorShotCount(); ++i)
        if (std::strcmp(editorShotAt(i)->name, name) == 0) return red ? editorShotAt(i)->red : editorShotAt(i)->white;
    return 0;
}
static int reloadChild() {
    wchar_t exe[32768]{};
    GetModuleFileNameW(nullptr, exe, 32768);
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --editor-load F:/rawrxd/kartgib/evidence/kartgib_editor_scene.txt";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) return 0;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    std::ifstream in("F:/rawrxd/kartgib/evidence/kartgib_editor_load.txt");
    std::string magic; int ver = 0, n = 0, id = 0, parent = 0; std::string name; float x = 0, y, z, yaw, scale;
    if (!(in >> magic >> ver >> n >> id >> parent >> name >> x >> y >> z >> yaw >> scale)) return 0;
    return code == 0 && closeTo(x, editorWitness().rx) ? 1 : 0;
}
bool editorFinish(Win32Window& window, VulkanRenderer& renderer) {
    static int step = 0;
    EditorWit& w = editorWitness();
    const EditorEnt* a = editorAt(0);
    HWND hwnd = window.getHandle();
    if (step == 0) {
        std::ofstream junk("F:/rawrxd/kartgib/evidence/kartgib_editor_scene.txt");
        junk << "NOPE\n"; junk.close();
        float keep = a->x;
        w.badLoad = !editorLoad("F:/rawrxd/kartgib/evidence/kartgib_editor_scene.txt") && closeTo(editorAt(0)->x, keep);
        SendMessage(hwnd, WM_KEYDOWN, VK_CONTROL, 0);
        SendMessage(hwnd, WM_KEYDOWN, 'S', 0);
        editorHandleInput(window);
        w.reload = reloadChild();
        SendMessage(hwnd, WM_KEYDOWN, 'P', 0);
        editorHandleInput(window);
        editorPlayStep();
        renderer.requestEditorShot("play");
        ++step; return true;
    }
    if (step == 1) {
        SendMessage(hwnd, WM_KEYDOWN, 'P', 0);
        editorHandleInput(window);
        renderer.requestEditorShot("stop");
        ++step; return true;
    }
    float bx, byaw, bs, b2; editorBootPose(bx, byaw, bs, b2);
    bool pick = w.pick == 1 && shotHash("select") != 0 && shotHash("select") != shotHash("base");
    bool gizmos = !closeTo(w.x, bx) && !closeTo(w.yaw, byaw) && !closeTo(w.scale, bs) && closeTo(w.x2, b2)
        && grid(w.x - bx, 0.5f) && grid(w.yaw, 15.0f * 3.14159265f / 180.0f) && grid(w.scale, 0.1f);
    bool inspector = shotTone("select", false) > 40 && shotTone("xform", false) > 40;
    bool hierarchy = w.dup && w.deleted && w.delMiss && w.renamed;
    bool undo = closeTo(w.ux, bx) && closeTo(w.uyaw, byaw) && closeTo(w.uscale, bs) && closeTo(w.rx, w.x) && closeTo(w.ryaw, w.yaw)
        && closeTo(w.rscale, w.scale) && shotHash("redo") == shotHash("xform") && shotHash("redo") != 0;
    bool save = w.reload && w.badLoad;
    bool play = shotHash("play") != shotHash("stop") && shotHash("stop") == shotHash("redo") && closeTo(a->x, w.rx);
    bool product = pick && gizmos && inspector && hierarchy && undo && save && play;
    char sha[65]{}; exeSha256(sha);
    char rev[80]{}, dirty[8]{};
    editorGit(rev, 80, dirty);
    std::ofstream json("F:/rawrxd/kartgib/evidence/KARTGIB_EDITOR_FINALIZATION_001.json");
    json << "{\"gate\":\"KARTGIB_EDITOR_FINALIZATION_001\",\"promote\":0"
         << ",\"batch25_exe_sha256\":\"1A9EF41B2616DBDFCEDE008157C4AF3A8A67093229976ECFC620AACD07DE1086\""
         << ",\"g32_exe_sha256\":\"6856E70A77A235A3AAF5DC440C22EFBC388E373180748BA0115A1482980BB3A6\""
         << ",\"exe_sha256\":\"" << sha << "\",\"source_revision\":\"" << rev << "\",\"dirty_tree\":\"" << dirty << "\""
         << ",\"EDITOR_MOUSE_PICK\":\"" << (pick ? "PASS" : "FAIL") << "\",\"EDITOR_GIZMOS\":\"" << (gizmos ? "PASS" : "FAIL")
         << "\",\"EDITOR_INSPECTOR\":\"" << (inspector ? "PASS" : "FAIL") << "\",\"EDITOR_HIERARCHY\":\"" << (hierarchy ? "PASS" : "FAIL")
         << "\",\"EDITOR_UNDO_REDO\":\"" << (undo ? "PASS" : "FAIL") << "\",\"EDITOR_SAVE_RELOAD\":\"" << (save ? "PASS" : "FAIL")
         << "\",\"EDITOR_PLAY_RESET\":\"" << (play ? "PASS" : "FAIL") << "\",\"G32_INTERACTIVE_PRODUCT\":\"" << (product ? "PASS" : "FAIL")
         << "\",\"pick\":" << w.pick << ",\"x\":" << w.x << ",\"yaw\":" << w.yaw << ",\"scale\":" << w.scale
         << ",\"undo_x\":" << w.ux << ",\"redo_x\":" << w.rx << ",\"reload\":" << w.reload
         << ",\"F02\":\"NOT_RUN\",\"F08\":\"NOT_RUN\",\"F10\":\"NOT_RUN\",\"F11\":\"NOT_RUN\",\"F13\":\"NOT_RUN\""
         << ",\"F14\":\"NOT_RUN\",\"F20\":\"NOT_RUN\",\"F21\":\"NOT_RUN\",\"F23\":\"NOT_RUN\",\"F24\":\"NOT_RUN\",\"F25\":\"NOT_RUN\""
         << ",\"save_kill\":\"NOT_RUN\"}\n";
    std::cout << "[EDITOR] pick=" << pick << " gizmos=" << gizmos << " undo=" << undo << " save=" << save << " play=" << play << std::endl;
    editorMarkDone();
    return false;
}
