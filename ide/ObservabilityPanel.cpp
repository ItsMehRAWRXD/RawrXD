#include "ide/ObservabilityPanel.hpp"
#include "ide/PanelState.hpp"
#include "observability/MetricsCollector.hpp"
#include "observability/DistributedTracer.hpp"
#include <imgui.h>
#include <cstring>

static char metricNameBuffer[64] = "";
static char traceIdBuffer[64] = "";

const char* ObservabilityPanel::Id() { return "ObservabilityPanel"; }
void ObservabilityPanel::Toggle() { PanelState::Toggle(Id()); }
bool ObservabilityPanel::IsWired() { return true; }
void ObservabilityPanel::Init() {}

void ObservabilityPanel::Render() {
    if (!PanelState::IsVisible(Id())) return;

    ImGui::Begin("Observability & Telemetry");

    // Metrics Collection
    if (ImGui::CollapsingHeader("Metrics Collection", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto metrics = MetricsCollector::GetMetrics();
        ImGui::Text("Total Metrics: %zu", metrics.size());
        
        ImGui::InputText("Metric Name", metricNameBuffer, sizeof(metricNameBuffer));
        
        if (ImGui::Button("Record Counter")) {
            if (strlen(metricNameBuffer) > 0) {
                MetricsCollector::RecordCounter(metricNameBuffer, 1.0);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Record Gauge")) {
            if (strlen(metricNameBuffer) > 0) {
                MetricsCollector::RecordGauge(metricNameBuffer, 42.0);
            }
        }
        
        if (ImGui::Button("Get Metric")) {
            if (strlen(metricNameBuffer) > 0) {
                auto metric = MetricsCollector::GetMetric(metricNameBuffer);
                ImGui::Text("Value: %.2f", metric.value("value", 0.0));
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Reset All")) {
            MetricsCollector::ResetAllMetrics();
        }
        
        // Display recent metrics
        ImGui::Text("Recent Metrics:");
        ImGui::BeginChild("metrics", ImVec2(0, 100), true);
        int count = 0;
        for (const auto& [name, data] : metrics.items()) {
            if (count++ > 20) break;
            ImGui::Text("%s: %.2f (%s)", name.get<std::string>().c_str(), 
                data.value("value", 0.0), data.value("type", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::Separator();
    
    // Distributed Tracing
    if (ImGui::CollapsingHeader("Distributed Tracing")) {
        auto activeTraces = DistributedTracer::GetActiveTraces();
        ImGui::Text("Active Traces: %zu", activeTraces.size());
        
        ImGui::InputText("Trace ID", traceIdBuffer, sizeof(traceIdBuffer));
        
        if (ImGui::Button("Start Trace")) {
            if (strlen(traceIdBuffer) > 0) {
                std::string traceId = DistributedTracer::StartTrace(traceIdBuffer);
                strncpy(traceIdBuffer, traceId.c_str(), sizeof(traceIdBuffer) - 1);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("End Trace")) {
            if (strlen(traceIdBuffer) > 0) {
                DistributedTracer::EndTrace(traceIdBuffer);
            }
        }
        
        if (ImGui::Button("Get Active Traces")) {
            auto traces = DistributedTracer::GetActiveTraces();
            ImGui::Text("Found %zu active traces", traces.size());
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear History")) {
            DistributedTracer::ClearTraceHistory();
        }
        
        // Display active traces
        ImGui::Text("Active Traces:");
        ImGui::BeginChild("traces", ImVec2(0, 80), true);
        for (const auto& trace : activeTraces) {
            ImGui::Text("%s [%s]", 
                trace.value("trace_id", "unknown").c_str(),
                trace.value("operation", "unknown").c_str());
        }
        ImGui::EndChild();
    }
    
    ImGui::End();
}
