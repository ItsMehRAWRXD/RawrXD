#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "win32_window.hpp"
#include <fstream>

bool studioScript(Win32Window& window, VulkanRenderer& renderer) {
    (void)window;
    if (!studioShowOnly()) return false;
    if (renderer.editorShotBusy()) return true;
    static int frames = 0;
    if (frames++ < 3) return true;
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
