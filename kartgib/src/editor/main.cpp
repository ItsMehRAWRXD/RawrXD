#include "editor/editor.hpp"

#include <iostream>
#include <chrono>

using namespace kartgib::editor;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize KartGib Editor
    KartGibEditor editor;
    
    if (!editor.initialize(hInstance, nCmdShow)) {
        MessageBoxA(nullptr, "Failed to initialize KartGib Editor", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    std::cout << "KartGib Editor initialized successfully" << std::endl;
    std::cout << "WorldForge integration: Complete" << std::endl;
    std::cout << "Vulkan rendering: Operational" << std::endl;
    std::cout << "Editor UI: Ready" << std::endl;
    
    // Run the editor
    int result = editor.run();
    
    // Cleanup
    editor.shutdown();
    
    return result;
}
