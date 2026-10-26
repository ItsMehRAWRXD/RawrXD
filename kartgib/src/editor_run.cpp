#include "editor_api.hpp"
#include "win32_window.hpp"
#include <cstring>
#include <fstream>
#include <iostream>

static EditorWit gWit;
EditorWit& editorWitness() { return gWit; }
bool editorScript(Win32Window& window, VulkanRenderer& renderer, int) {
    if (editorShowOnly()) {
        static int shown = 0;
        if (renderer.editorShotBusy()) return true;
        static int frames = 0;
        if (frames++ < 3) return true;
        if (!shown) { renderer.requestEditorShot("reload"); shown = 1; return true; }
        editorMarkDone();
        return false;
    }
    if (renderer.editorShotBusy()) return true;
    static int frames = 0;
    if (frames++ < 3) return true;
    static int phase = 0;
    HWND hwnd = window.getHandle();
    const EditorEnt* a = editorAt(0);
    const EditorEnt* b = editorAt(1);
    switch (phase++) {
    case 0: {
        int n = editorCount();
        editorDuplicate(1);
        gWit.dup = editorCount() == n + 1;
        int copy = editorAt(editorCount() - 1)->id;
        editorRename(copy, "Copy");
        gWit.renamed = std::strcmp(editorAt(editorCount() - 1)->name, "Copy") == 0;
        gWit.delMiss = !editorDelete(99) ? 1 : 0;
        gWit.deleted = editorDelete(copy) && editorCount() == n;
        editorClearJournal();
        std::ofstream bad("F:/rawrxd/kartgib/evidence/kartgib_editor_bad.txt");
        bad << "NOPE\n"; bad.close();
        float keep = a->x;
        gWit.badLoad = !editorLoad("F:/rawrxd/kartgib/evidence/kartgib_editor_bad.txt") && editorAt(0)->x == keep;
        renderer.requestEditorShot("base");
        break;
    }
    case 1: {
        int px = 0, py = 0;
        editorProjectId(window, 1, -1, px, py);
        std::cout << "[EDITOR] pick pixel " << px << "," << py << std::endl;
        editorDrag(window, px, py, px, py);
        editorHandleInput(window);
        gWit.pick = editorSelected();
        renderer.requestEditorShot("select");
        break;
    }
    case 2:
        editorGesture(window, 'T', 0, 0);
        editorTap(window, 'L');
        editorGesture(window, 'R', 0, 160);
        editorGesture(window, 'S', 0, 160);
        gWit.local = editorLocal() ? 1 : 0;
        gWit.x = a->x; gWit.y = a->y; gWit.z = a->z; gWit.yaw = a->yaw; gWit.scale = a->scale; gWit.x2 = b->x;
        renderer.requestEditorShot("xform");
        break;
    case 3:
        for (int i = 0; i < 3; ++i) { editorTap(window, VK_CONTROL); editorTap(window, 'Z'); editorHandleInput(window); }
        gWit.ux = a->x; gWit.uyaw = a->yaw; gWit.uscale = a->scale;
        renderer.requestEditorShot("undo");
        break;
    case 4:
        for (int i = 0; i < 3; ++i) { editorTap(window, VK_CONTROL); editorTap(window, 'Y'); editorHandleInput(window); }
        gWit.rx = a->x; gWit.ryaw = a->yaw; gWit.rscale = a->scale; gWit.rx2 = b->x;
        renderer.requestEditorShot("redo");
        break;
    default:
        return editorFinish(window, renderer);
    }
    return true;
}
