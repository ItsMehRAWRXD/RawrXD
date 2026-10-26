#include "editor_api.hpp"
#include "win32_window.hpp"
#include "worldforge.hpp"
#include <cmath>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

static const char* kDir = "F:/rawrxd/kartgib/evidence/studio_project";
static int reloadChild(float expect) {
    wchar_t exe[32768]{}; GetModuleFileNameW(nullptr, exe, 32768);
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --studio-load";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) return 0;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    std::ifstream in("F:/rawrxd/kartgib/evidence/studio_peak.txt");
    float y = 0; in >> y;
    return code == 0 && std::fabs(y - expect) < 0.05f;
}
bool studioScript(Win32Window& window, VulkanRenderer& renderer) {
    if (studioShowOnly()) {
        static int frames = 0;
        if (renderer.editorShotBusy()) return true;
        if (frames++ < 3) return true;
        std::ofstream out("F:/rawrxd/kartgib/evidence/studio_peak.txt");
        out << studioMeshY() << "\n";
        editorMarkDone();
        return false;
    }
    if (renderer.editorShotBusy()) return true;
    static int frames = 0;
    if (frames++ < 3) return true;
    static int phase = 0;
    const EditorEnt* a = editorAt(0);
    const EditorEnt* b = editorAt(1);
    switch (phase++) {
    case 0:
        std::cout << "[STUDIO] project=" << studioCreateProject(kDir) << " terrain=" << studioTerrainVerts() << std::endl;
        renderer.requestEditorShot("studio_ground");
        break;
    case 1: {
        editorTap(window, 'B'); editorHandleInput(window);
        kg::Settings settings; settings.seed = 20261025; settings.biome = kg::Biome::Tropical;
        float h = static_cast<float>(kg::sampleHeight(-10.0, 0.0, settings));
        float view[16], proj[16]; int px = 0, py = 0; float depth = 0;
        editorCamera(view, proj, window.getWidth(), window.getHeight());
        editorProject(view, proj, -10.0f, h, 0.0f, window.getWidth(), window.getHeight(), px, py, depth);
        std::cout << "[STUDIO] sculpt pixel " << px << "," << py << std::endl;
        editorDrag(window, px, py, px, py); editorHandleInput(window);
        std::cout << "[STUDIO] height " << studioBaseY() << " -> " << studioMeshY() << std::endl;
        renderer.requestEditorShot("studio_sculpt");
        break;
    }
    case 2: {
        editorTap(window, 'T'); editorHandleInput(window);
        int px = 0, py = 0; editorProjectId(window, 1, -1, px, py);
        editorDrag(window, px, py, px, py); editorHandleInput(window);
        editorGesture(window, 'T', 0, 0);
        std::cout << "[STUDIO] pick=" << editorSelected() << " x=" << a->x << std::endl;
        renderer.requestEditorShot("studio_xform");
        break;
    }
    case 3:
        sunshineScene("rename 1 Ridge");
        sunshineScene("transform 2 40 14 36 0 1.3");
        std::cout << "[STUDIO] name=" << a->name << " b=" << b->x << std::endl;
        break;
    case 4:
        for (int i = 0; i < 4; ++i) editorUndo();
        std::cout << "[STUDIO] undo y=" << studioMeshY() << " x=" << a->x << " name=" << a->name << " b=" << b->x << std::endl;
        break;
    case 5:
        for (int i = 0; i < 4; ++i) editorRedo();
        std::cout << "[STUDIO] redo y=" << studioMeshY() << " x=" << a->x << std::endl;
        break;
    default: {
        bool saved = studioSaveProject(kDir);
        int child = reloadChild(studioMeshY());
        float z0 = a->z;
        sunshineScene("play"); editorPlayStep();
        float played = a->z;
        sunshineScene("play");
        std::cout << "[STUDIO] save=" << saved << " reload=" << child << " play=" << played << " stop=" << a->z << " z0=" << z0 << std::endl;
        editorMarkDone();
        return false;
    }
    }
    return true;
}
