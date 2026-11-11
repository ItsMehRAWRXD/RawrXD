#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "win32_window.hpp"
#include <fstream>

bool studioScript(Win32Window& window, VulkanRenderer& renderer) {
    (void)window;
    if (studioEditor2() && studioShowOnly()) {
        if (renderer.editorShotBusy()) return true;
        static int warm = 0;
        if (warm++ < 3) return true;
        inspectorApplyEditor2();
        std::ofstream out("F:/rawrxd/kartgib/evidence/studio_editor2_peak.txt");
        for (int i = 0; i < editorCount(); ++i) {
            const EditorEnt* e = editorAt(i);
            out << e->id << " " << e->parent << " " << e->x << " " << e->y << " " << e->z << " " << e->yaw << " " << e->scale << "\n";
        }
        int d = 0, x = 0, y = 0, w = 0, h = 0; inspectorDockInfo(d, x, y, w, h);
        out << "layout " << d << " " << x << " " << y << " " << w << " " << h << "\n";
        editorMarkDone();
        return false;
    }
    if (!studioShowOnly()) return false;
    if (renderer.editorShotBusy()) return true;
    static int frames = 0;
    if (frames++ < 3) return true;
    static int shot = 0;
    if (!shot) { renderer.requestEditorShot("gui_reload"); shot = 1; return true; }
    std::ifstream brush("F:/rawrxd/kartgib/evidence/studio_project/brush.txt");
    int mode = 0; float radius = 0, strength = 0, fall = 0;
    if (brush >> mode >> radius >> strength >> fall) studioSetBrush(mode, radius, strength, fall);
    std::ofstream out("F:/rawrxd/kartgib/evidence/studio_peak.txt");
    const EditorEnt* e = editorAt(0);
    out << studioMeshY() << " " << (e ? e->x : 0) << " " << studioBrush().radius << " " << inspectorWidth()
        << " " << (e ? e->yaw : 0) << " " << (e ? e->scale : 0) << "\n";
    editorMarkDone();
    return false;
}
