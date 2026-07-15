#pragma once

#include <cstring>

namespace RawrXD {
namespace IDE {

class EmergencePanel {
public:
    static void Init();
    static void Render();
    static void Toggle();
    static bool IsVisible();
    static const char* Id();

private:
    static bool s_visible;
    static int s_selectedPattern;
    static int s_selectedStructure;
    static int s_selectedBehavior;
};

} // namespace IDE
} // namespace RawrXD
