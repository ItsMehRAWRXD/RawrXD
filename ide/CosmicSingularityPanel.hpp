#pragma once

#include <imgui.h>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace Singularity {

class CosmicSingularityLoop;

struct CosmicSingularityPanelState {
    bool showConsciousnessCores = true;
    bool showThoughtStreams = true;
    bool showMemoryMatrices = true;
    bool showPerceptionFields = true;
    bool showIntentionVectors = true;
    bool showMetrics = true;
    bool showEventLog = true;
    char newCoreName[256] = "";
    char newMatrixName[256] = "";
    char newFieldName[256] = "";
    char newVectorName[256] = "";
    char selectedCoreId[256] = "";
    char selectedThoughtType[256] = "";
    int tickRate = 60;
    bool loopRunning = false;
    std::vector<std::string> eventLog;
};

class CosmicSingularityPanel {
public:
    CosmicSingularityPanel();
    ~CosmicSingularityPanel();

    void Initialize();
    void Shutdown();
    void Render(const char* title = "Cosmic Singularity (Layer 66)");
    bool IsVisible() const;
    void SetVisible(bool visible);
    void ToggleVisibility();
    void OnTick();
    void OnSingularityEvent(const std::string& event);
    CosmicSingularityPanelState& GetState();

private:
    void RenderConsciousnessCoresTab();
    void RenderThoughtStreamsTab();
    void RenderMemoryMatricesTab();
    void RenderPerceptionFieldsTab();
    void RenderIntentionVectorsTab();
    void RenderMetricsTab();
    void RenderEventLogTab();
    void UpdateMetrics();

    bool m_visible;
    bool m_initialized;
    CosmicSingularityPanelState m_state;
    CosmicSingularityLoop* m_loop;
    nlohmann::json m_currentMetrics;
    mutable std::mutex m_metricsMutex;
};

} // namespace Singularity
