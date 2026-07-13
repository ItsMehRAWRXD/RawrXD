#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace Neural {

class NeuralSingularityLoop;

struct NeuralSingularityPanelState {
    bool showNeuralClusters = true;
    bool showSynapticPathways = true;
    bool showActivationPatterns = true;
    bool showPlasticityZones = true;
    bool showCognitiveResonances = true;
    bool showMetrics = true;
    bool showEventLog = true;
    char newClusterName[256] = "";
    char newZoneName[256] = "";
    char selectedClusterId[256] = "";
    char selectedPatternType[256] = "";
    int neuronCount = 100;
    int tickRate = 60;
    bool loopRunning = false;
    std::vector<std::string> eventLog;
};

class NeuralSingularityPanel {
public:
    NeuralSingularityPanel();
    ~NeuralSingularityPanel();

    void Initialize();
    void Shutdown();
    void Render(const char* title = "Neural Singularity (Layer 68)");
    bool IsVisible() const;
    void SetVisible(bool visible);
    void ToggleVisibility();
    void OnTick();
    void OnNeuralEvent(const std::string& event);
    NeuralSingularityPanelState& GetState();

private:
    void RenderNeuralClustersTab();
    void RenderSynapticPathwaysTab();
    void RenderActivationPatternsTab();
    void RenderPlasticityZonesTab();
    void RenderCognitiveResonancesTab();
    void RenderMetricsTab();
    void RenderEventLogTab();
    void UpdateMetrics();

    bool m_visible;
    bool m_initialized;
    NeuralSingularityPanelState m_state;
    NeuralSingularityLoop* m_loop;
    nlohmann::json m_currentMetrics;
    mutable std::mutex m_metricsMutex;
};

} // namespace Neural
