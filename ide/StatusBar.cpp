#include "ide/StatusBar.hpp"
#include "ide/SystemHealthIndicator.hpp"
#include "sovereign/SovereignTelemetry.hpp"
#include <imgui.h>

void StatusBar::Init() {}

void StatusBar::Render() {
    ImGui::Begin("StatusBar", nullptr,
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoSavedSettings);

    ImGui::Text("Latency: %llu us", Telemetry::Collect().GpuLatencyUs);

    ImGui::SameLine(300);
    SystemHealthIndicator::Render();

    ImGui::End();
}
