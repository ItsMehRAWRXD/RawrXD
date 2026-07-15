#pragma once
#include <string>

class GalacticPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static void Toggle();
    static bool IsVisible();
    static std::string Id();
    
private:
    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
};
