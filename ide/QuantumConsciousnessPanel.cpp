#include "ide/QuantumConsciousnessPanel.hpp"
#include "quantum/QuantumConsciousnessEngine.hpp"
#include "quantum/QuantumConsciousnessLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace Quantum {

QuantumConsciousnessPanel::QuantumConsciousnessPanel()
    : m_visible(false)
    , m_initialized(false)
    , m_loop(nullptr)
{
    m_currentMetrics = nlohmann::json::object();
}

QuantumConsciousnessPanel::~QuantumConsciousnessPanel() {
    Shutdown();
}

void QuantumConsciousnessPanel::Initialize() {
    if (m_initialized) return;
    QuantumConsciousnessEngine::Init();
    m_loop = new QuantumConsciousnessLoop();
    m_loop->RegisterTickCallback([this]() { OnTick(); });
    m_loop->RegisterQuantumCallback([this](const std::string& event) { OnQuantumEvent(event); });
    m_initialized = true;
}

void QuantumConsciousnessPanel::Shutdown() {
    if (!m_initialized) return;
    if (m_loop) {
        m_loop->Stop();
        delete m_loop;
        m_loop = nullptr;
    }
    QuantumConsciousnessEngine::Shutdown();
    m_initialized = false;
}

void QuantumConsciousnessPanel::Render(const char* title) {
    if (!m_visible || !m_initialized) return;

    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(title, &m_visible)) {
        if (ImGui::Button(m_loop->IsRunning() ? "Stop Loop" : "Start Loop")) {
            if (m_loop->IsRunning()) {
                m_loop->Stop();
                m_state.loopRunning = false;
            } else {
                m_loop->Start();
                m_state.loopRunning = true;
            }
        }
        ImGui::SameLine();
        ImGui::SliderInt("Tick Rate", &m_state.tickRate, 1, 120);
        m_loop->SetTickRate(m_state.tickRate);
        ImGui::SameLine();
        ImGui::Text("Ticks: %lld", m_loop->GetTickCount());

        if (ImGui::BeginTabBar("QuantumConsciousnessTabs")) {
            if (m_state.showQuantumStates && ImGui::BeginTabItem("Quantum States")) {
                RenderQuantumStatesTab();
                ImGui::EndTabItem();
            }
            if (m_state.showWaveFunctions && ImGui::BeginTabItem("Wave Functions")) {
                RenderWaveFunctionsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showEntanglementNodes && ImGui::BeginTabItem("Entanglement Nodes")) {
                RenderEntanglementNodesTab();
                ImGui::EndTabItem();
            }
            if (m_state.showProbabilityClouds && ImGui::BeginTabItem("Probability Clouds")) {
                RenderProbabilityCloudsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showObserverEffects && ImGui::BeginTabItem("Observer Effects")) {
                RenderObserverEffectsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showMetrics && ImGui::BeginTabItem("Metrics")) {
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showEventLog && ImGui::BeginTabItem("Event Log")) {
                RenderEventLogTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

bool QuantumConsciousnessPanel::IsVisible() const {
    return m_visible;
}

void QuantumConsciousnessPanel::SetVisible(bool visible) {
    m_visible = visible;
}

void QuantumConsciousnessPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

void QuantumConsciousnessPanel::OnTick() {
    UpdateMetrics();
}

void QuantumConsciousnessPanel::OnQuantumEvent(const std::string& event) {
    m_state.eventLog.push_back(event);
    if (m_state.eventLog.size() > 100) {
        m_state.eventLog.erase(m_state.eventLog.begin());
    }
}

QuantumConsciousnessPanelState& QuantumConsciousnessPanel::GetState() {
    return m_state;
}

void QuantumConsciousnessPanel::RenderQuantumStatesTab() {
    ImGui::Text("Create New Quantum State:");
    ImGui::InputText("State Name", m_state.newStateName, sizeof(m_state.newStateName));
    if (ImGui::Button("Create")) {
        if (strlen(m_state.newStateName) > 0) {
            QuantumConsciousnessEngine::CreateQuantumState(m_state.newStateName);
            m_state.newStateName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Quantum States:");
    auto states = QuantumConsciousnessEngine::GetAllStates();
    if (ImGui::BeginTable("StatesTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Superposition");
        ImGui::TableSetupColumn("Coherence");
        ImGui::TableSetupColumn("Entanglement");
        ImGui::TableHeadersRow();
        for (const auto& state : states) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", state.stateId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", state.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", state.superposition);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", state.coherence);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", state.entanglement);
        }
        ImGui::EndTable();
    }
}

void QuantumConsciousnessPanel::RenderWaveFunctionsTab() {
    ImGui::Text("Initialize Wave Function:");
    ImGui::InputText("State ID", m_state.selectedStateId, sizeof(m_state.selectedStateId));
    ImGui::InputText("Wave Type", m_state.selectedWaveType, sizeof(m_state.selectedWaveType));
    if (ImGui::Button("Initialize")) {
        if (strlen(m_state.selectedStateId) > 0 && strlen(m_state.selectedWaveType) > 0) {
            QuantumConsciousnessEngine::InitializeWaveFunction(m_state.selectedStateId, m_state.selectedWaveType);
            m_state.selectedWaveType[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Wave Functions:");
    auto functions = QuantumConsciousnessEngine::GetAllWaveFunctions();
    if (ImGui::BeginTable("WaveFunctionsTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Frequency");
        ImGui::TableSetupColumn("Phase");
        ImGui::TableSetupColumn("Amplitude");
        ImGui::TableHeadersRow();
        for (const auto& func : functions) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", func.functionId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", func.waveType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", func.frequency);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", func.phase);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", func.amplitude);
        }
        ImGui::EndTable();
    }
}

void QuantumConsciousnessPanel::RenderEntanglementNodesTab() {
    ImGui::Text("Create Entanglement Node:");
    ImGui::InputText("Node Name", m_state.newNodeName, sizeof(m_state.newNodeName));
    ImGui::InputText("Node Type", m_state.selectedNodeType, sizeof(m_state.selectedNodeType));
    if (ImGui::Button("Create")) {
        if (strlen(m_state.newNodeName) > 0 && strlen(m_state.selectedNodeType) > 0) {
            QuantumConsciousnessEngine::CreateEntanglementNode(m_state.newNodeName, m_state.selectedNodeType);
            m_state.newNodeName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Entanglement Nodes:");
    auto nodes = QuantumConsciousnessEngine::GetAllNodes();
    if (ImGui::BeginTable("NodesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Correlation");
        ImGui::TableHeadersRow();
        for (const auto& node : nodes) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", node.nodeId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", node.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", node.nodeType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", node.correlation);
        }
        ImGui::EndTable();
    }
}

void QuantumConsciousnessPanel::RenderProbabilityCloudsTab() {
    ImGui::Text("Form Probability Cloud:");
    ImGui::InputText("Cloud Name", m_state.newCloudName, sizeof(m_state.newCloudName));
    ImGui::InputText("Cloud Type", m_state.selectedCloudType, sizeof(m_state.selectedCloudType));
    if (ImGui::Button("Form")) {
        if (strlen(m_state.newCloudName) > 0 && strlen(m_state.selectedCloudType) > 0) {
            QuantumConsciousnessEngine::FormProbabilityCloud(m_state.newCloudName, m_state.selectedCloudType);
            m_state.newCloudName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Probability Clouds:");
    auto clouds = QuantumConsciousnessEngine::GetAllClouds();
    if (ImGui::BeginTable("CloudsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Density");
        ImGui::TableHeadersRow();
        for (const auto& cloud : clouds) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", cloud.cloudId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", cloud.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", cloud.cloudType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", cloud.density);
        }
        ImGui::EndTable();
    }
}

void QuantumConsciousnessPanel::RenderObserverEffectsTab() {
    ImGui::Text("Observer Effects:");
    auto effects = QuantumConsciousnessEngine::GetAllEffects();
    if (ImGui::BeginTable("EffectsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Observer");
        ImGui::TableSetupColumn("Observed State");
        ImGui::TableSetupColumn("Influence");
        ImGui::TableHeadersRow();
        for (const auto& effect : effects) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", effect.effectId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", effect.observerId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", effect.observedState.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", effect.influence);
        }
        ImGui::EndTable();
    }
}

void QuantumConsciousnessPanel::RenderMetricsTab() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    ImGui::Text("Quantum Metrics:");
    if (m_currentMetrics.contains("stateCount")) {
        ImGui::Text("Quantum States: %d", m_currentMetrics["stateCount"].get<int>());
        ImGui::Text("Wave Functions: %d", m_currentMetrics["waveFunctionCount"].get<int>());
        ImGui::Text("Entanglement Nodes: %d", m_currentMetrics["nodeCount"].get<int>());
        ImGui::Text("Probability Clouds: %d", m_currentMetrics["cloudCount"].get<int>());
        ImGui::Text("Observer Effects: %d", m_currentMetrics["effectCount"].get<int>());
        ImGui::Separator();
        ImGui::Text("Total Coherence: %.3f", m_currentMetrics["totalCoherence"].get<float>());
        ImGui::Text("Average Entanglement: %.3f", m_currentMetrics["averageEntanglement"].get<float>());
        ImGui::Text("Entanglement Count: %d", m_currentMetrics["entanglementCount"].get<int>());
        ImGui::Text("Tick Count: %lld", m_currentMetrics["tickCount"].get<int64_t>());
    }
}

void QuantumConsciousnessPanel::RenderEventLogTab() {
    ImGui::Text("Recent Quantum Events:");
    ImGui::BeginChild("EventLog", ImVec2(0, 400), true);
    for (const auto& event : m_state.eventLog) {
        ImGui::Text("%s", event.c_str());
    }
    ImGui::EndChild();
    if (ImGui::Button("Clear Log")) {
        m_state.eventLog.clear();
    }
}

void QuantumConsciousnessPanel::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    m_currentMetrics = QuantumConsciousnessEngine::GetQuantumMetrics();
}

} // namespace Quantum
