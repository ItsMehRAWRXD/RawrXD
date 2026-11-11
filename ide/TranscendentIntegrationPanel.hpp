#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace Transcendent {

class TranscendentIntegrationLoop;

struct TranscendentIntegrationPanelState {
    bool showTranscendentNodes = true;
    bool showAscensionPaths = true;
    bool showDivineSparks = true;
    bool showEternalFlames = true;
    bool showCosmicHarmonies = true;
    bool showMetrics = true;
    bool showEventLog = true;
    char newNodeName[256] = "";
    char newPathName[256] = "";
    char newSparkName[256] = "";
    char newFlameName[256] = "";
    char newHarmonyName[256] = "";
    char selectedNodeType[256] = "";
    char selectedSource[256] = "";
    char selectedTarget[256] = "";
    int tickRate = 60;
    bool loopRunning = false;
    std::vector<std::string> eventLog;
};

class TranscendentIntegrationPanel {
public:
    TranscendentIntegrationPanel();
    ~TranscendentIntegrationPanel();

    void Initialize();
    void Shutdown();
    void Render(const char* title = "Transcendent Integration (Layer 71)");
    bool IsVisible() const;
    void SetVisible(bool visible);
    void ToggleVisibility();
    void OnTick();
    void OnTranscendentEvent(const std::string& event);
    TranscendentIntegrationPanelState& GetState();

private:
    void RenderTranscendentNodesTab();
    void RenderAscensionPathsTab();
    void RenderDivineSparksTab();
    void RenderEternalFlamesTab();
    void RenderCosmicHarmoniesTab();
    void RenderMetricsTab();
    void RenderEventLogTab();
    void UpdateMetrics();

    bool m_visible;
    bool m_initialized;
    TranscendentIntegrationPanelState m_state;
    TranscendentIntegrationLoop* m_loop;
    nlohmann::json m_currentMetrics;
    mutable std::mutex m_metricsMutex;
};

} // namespace Transcendent
