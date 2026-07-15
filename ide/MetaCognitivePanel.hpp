#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace MetaCognitive {

class MetaCognitiveLoop;

struct MetaCognitivePanelState {
    bool showReflectionPools = true;
    bool showIntrospectionModules = true;
    bool showSelfModels = true;
    bool showAwarenessMonitors = true;
    bool showCognitiveBiases = true;
    bool showMetrics = true;
    bool showEventLog = true;
    char newPoolName[256] = "";
    char newModuleName[256] = "";
    char newModelName[256] = "";
    char selectedTarget[256] = "";
    char selectedType[256] = "";
    int tickRate = 60;
    bool loopRunning = false;
    std::vector<std::string> eventLog;
};

class MetaCognitivePanel {
public:
    MetaCognitivePanel();
    ~MetaCognitivePanel();

    void Initialize();
    void Shutdown();
    void Render(const char* title = "Meta-Cognitive (Layer 70)");
    bool IsVisible() const;
    void SetVisible(bool visible);
    void ToggleVisibility();
    void OnTick();
    void OnMetaCognitiveEvent(const std::string& event);
    MetaCognitivePanelState& GetState();

private:
    void RenderReflectionPoolsTab();
    void RenderIntrospectionModulesTab();
    void RenderSelfModelsTab();
    void RenderAwarenessMonitorsTab();
    void RenderCognitiveBiasesTab();
    void RenderMetricsTab();
    void RenderEventLogTab();
    void UpdateMetrics();

    bool m_visible;
    bool m_initialized;
    MetaCognitivePanelState m_state;
    MetaCognitiveLoop* m_loop;
    nlohmann::json m_currentMetrics;
    mutable std::mutex m_metricsMutex;
};

} // namespace MetaCognitive
