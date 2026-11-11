#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace Quantum {

class QuantumConsciousnessLoop;

struct QuantumConsciousnessPanelState {
    bool showQuantumStates = true;
    bool showWaveFunctions = true;
    bool showEntanglementNodes = true;
    bool showProbabilityClouds = true;
    bool showObserverEffects = true;
    bool showMetrics = true;
    bool showEventLog = true;
    char newStateName[256] = "";
    char newNodeName[256] = "";
    char newCloudName[256] = "";
    char selectedStateId[256] = "";
    char selectedWaveType[256] = "";
    char selectedNodeType[256] = "";
    char selectedCloudType[256] = "";
    int tickRate = 60;
    bool loopRunning = false;
    std::vector<std::string> eventLog;
};

class QuantumConsciousnessPanel {
public:
    QuantumConsciousnessPanel();
    ~QuantumConsciousnessPanel();

    void Initialize();
    void Shutdown();
    void Render(const char* title = "Quantum Consciousness (Layer 67)");
    bool IsVisible() const;
    void SetVisible(bool visible);
    void ToggleVisibility();
    void OnTick();
    void OnQuantumEvent(const std::string& event);
    QuantumConsciousnessPanelState& GetState();

private:
    void RenderQuantumStatesTab();
    void RenderWaveFunctionsTab();
    void RenderEntanglementNodesTab();
    void RenderProbabilityCloudsTab();
    void RenderObserverEffectsTab();
    void RenderMetricsTab();
    void RenderEventLogTab();
    void UpdateMetrics();

    bool m_visible;
    bool m_initialized;
    QuantumConsciousnessPanelState m_state;
    QuantumConsciousnessLoop* m_loop;
    nlohmann::json m_currentMetrics;
    mutable std::mutex m_metricsMutex;
};

} // namespace Quantum
