#include "ide/SystemHealthIndicator.hpp"
#include "sovereign/SovereignSelfCheck.hpp"
#include "ide/DrawPrimitives.hpp"
#include <imgui.h>

void SystemHealthIndicator::Render() {
    auto results = SovereignSelfCheck::RunAll();

    bool allOk = true;
    for (auto& r : results)
        if (!r.ok) { allOk = false; break; }

    if (allOk)
        DrawPrimitives::GreenLight("ALL SYSTEMS GREEN");
    else
        DrawPrimitives::RedLight("SYSTEM ISSUES DETECTED");
}
