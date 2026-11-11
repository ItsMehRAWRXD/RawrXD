#include "tests/FabricStressTester.hpp"
#include "sovereign/Fabric.hpp"
#include "sovereign/SovereignTelemetry.hpp"
#include <chrono>
#include <imgui.h>

void FabricStressTester::Init() {}

void FabricStressTester::RunOnce() {
    auto start = std::chrono::high_resolution_clock::now();

    Fabric::BroadcastJSON({{"type","stress_ping"}});
    auto t = Telemetry::Collect();

    auto end = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    ImGui::Text("Stress latency: %lld us", us);
    ImGui::Text("GPU latency: %llu us", t.GpuLatencyUs);
}

void FabricStressTester::RunLoop(int iterations) {
    for (int i = 0; i < iterations; i++) {
        RunOnce();
    }
}
