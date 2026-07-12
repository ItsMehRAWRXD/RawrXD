#pragma once

#include <string>

namespace RawrXD {
namespace IDE {

class EthicsPanel {
public:
    static void Init();
    static void Render();
    static void Toggle();
    static bool IsVisible();
    static const char* Id();

private:
    static bool s_visible;
    static int s_selectedPrinciple;
    static int s_selectedDilemma;
    static int s_selectedEvaluation;
};

} // namespace IDE
} // namespace RawrXD
