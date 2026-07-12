#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace Synthetic {

class SyntheticConsciousnessLoop;

struct SyntheticConsciousnessPanelState {
    bool showSyntheticMinds = true;
    bool showEmulationLayers = true;
    bool showCognitiveTemplates = true;
    bool showConsciousnessForks = true;
    bool showSubstrateBridges = true;
    bool showMetrics = true;
    bool showEventLog = true;
    char newMindName[256] = "";
    char newLayerName[256] = "";
    char newTemplateName[256] = "";
    char selectedSubstrate[256] = "";
    char selectedTarget[256] = "";
    char selectedType[256] = "";
    int tickRate = 60;
    bool loopRunning = false;
    std::vector<std::string> eventLog;
};

class SyntheticConsciousnessPanel {
public:
    SyntheticConsciousnessPanel();
    ~SyntheticConsciousnessPanel();

    void Initialize();
    void Shutdown();
    void Render(const char* title = "Synthetic Consciousness (Layer 69)");
    bool IsVisible() const;
    void SetVisible(bool visible);
    void ToggleVisibility();
    void OnTick();
    void OnSyntheticEvent(const std::string& event);
    SyntheticConsciousnessPanelState& GetState();

private:
    void RenderSyntheticMindsTab();
    void RenderEmulationLayersTab();
    void RenderCognitiveTemplatesTab();
    void RenderConsciousnessForksTab();
    void RenderSubstrateBridgesTab();
    void RenderMetricsTab();
    void RenderEventLogTab();
    void UpdateMetrics();

    bool m_visible;
    bool m_initialized;
    SyntheticConsciousnessPanelState m_state;
    SyntheticConsciousnessLoop* m_loop;
    nlohmann::json m_currentMetrics;
    mutable std::mutex m_metricsMutex;
};

} // namespace Synthetic
