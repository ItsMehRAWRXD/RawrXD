#include "ide/NeuralSingularityPanel.hpp"
#include "neural/NeuralSingularityEngine.hpp"
#include "neural/NeuralSingularityLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace Neural {

NeuralSingularityPanel::NeuralSingularityPanel()
    : m_visible(false)
    , m_initialized(false)
    , m_loop(nullptr)
{
    m_currentMetrics = nlohmann::json::object();
}

NeuralSingularityPanel::~NeuralSingularityPanel() {
    Shutdown();
}

void NeuralSingularityPanel::Initialize() {
    if (m_initialized) return;
    NeuralSingularityEngine::Init();
    m_loop = new NeuralSingularityLoop();
    m_loop->RegisterTickCallback([this]() { OnTick(); });
    m_loop->RegisterNeuralCallback([this](const std::string& event) { OnNeuralEvent(event); });
    m_initialized = true;
}

void NeuralSingularityPanel::Shutdown() {
    if (!m_initialized) return;
    if (m_loop) {
        m_loop->Stop();
        delete m_loop;
        m_loop = nullptr;
    }
    NeuralSingularityEngine::Shutdown();
    m_initialized = false;
}

void NeuralSingularityPanel::Render(const char* title) {
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

        if (ImGui::BeginTabBar("NeuralSingularityTabs")) {
            if (m_state.showNeuralClusters && ImGui::BeginTabItem("Neural Clusters")) {
                RenderNeuralClustersTab();
                ImGui::EndTabItem();
            }
            if (m_state.showSynapticPathways && ImGui::BeginTabItem("Synaptic Pathways")) {
                RenderSynapticPathwaysTab();
                ImGui::EndTabItem();
            }
            if (m_state.showActivationPatterns && ImGui::BeginTabItem("Activation Patterns")) {
                RenderActivationPatternsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showPlasticityZones && ImGui::BeginTabItem("Plasticity Zones")) {
                RenderPlasticityZonesTab();
                ImGui::EndTabItem();
            }
            if (m_state.showCognitiveResonances && ImGui::BeginTabItem("Cognitive Resonances")) {
                RenderCognitiveResonancesTab();
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

bool NeuralSingularityPanel::IsVisible() const {
    return m_visible;
}

void NeuralSingularityPanel::SetVisible(bool visible) {
    m_visible = visible;
}

void NeuralSingularityPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

void NeuralSingularityPanel::OnTick() {
    UpdateMetrics();
}

void NeuralSingularityPanel::OnNeuralEvent(const std::string& event) {
    m_state.eventLog.push_back(event);
    if (m_state.eventLog.size() > 100) {
        m_state.eventLog.erase(m_state.eventLog.begin());
    }
}

NeuralSingularityPanelState& NeuralSingularityPanel::GetState() {
    return m_state;
}

void NeuralSingularityPanel::RenderNeuralClustersTab() {
    ImGui::Text("Form New Neural Cluster:");
    ImGui::InputText("Cluster Name", m_state.newClusterName, sizeof(m_state.newClusterName));
    ImGui::InputInt("Neuron Count", &m_state.neuronCount);
    if (ImGui::Button("Form")) {
        if (strlen(m_state.newClusterName) > 0) {
            NeuralSingularityEngine::FormNeuralCluster(m_state.newClusterName, m_state.neuronCount);
            m_state.newClusterName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Neural Clusters:");
    auto clusters = NeuralSingularityEngine::GetAllClusters();
    if (ImGui::BeginTable("ClustersTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Neurons");
        ImGui::TableSetupColumn("Activation");
        ImGui::TableSetupColumn("Plasticity");
        ImGui::TableHeadersRow();
        for (const auto& cluster : clusters) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", cluster.clusterId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", cluster.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%d", cluster.neuronCount);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", cluster.activationLevel);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", cluster.plasticity);
        }
        ImGui::EndTable();
    }
}

void NeuralSingularityPanel::RenderSynapticPathwaysTab() {
    ImGui::Text("Active Synaptic Pathways:");
    auto pathways = NeuralSingularityEngine::GetAllPathways();
    if (ImGui::BeginTable("PathwaysTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Target");
        ImGui::TableSetupColumn("Strength");
        ImGui::TableSetupColumn("Active");
        ImGui::TableHeadersRow();
        for (const auto& pathway : pathways) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", pathway.pathwayId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", pathway.sourceCluster.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", pathway.targetCluster.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", pathway.strength);
            ImGui::TableNextColumn(); ImGui::Text("%s", pathway.isActive ? "Yes" : "No");
        }
        ImGui::EndTable();
    }
}

void NeuralSingularityPanel::RenderActivationPatternsTab() {
    ImGui::Text("Trigger Activation Pattern:");
    ImGui::InputText("Cluster ID", m_state.selectedClusterId, sizeof(m_state.selectedClusterId));
    ImGui::InputText("Pattern Type", m_state.selectedPatternType, sizeof(m_state.selectedPatternType));
    if (ImGui::Button("Trigger")) {
        if (strlen(m_state.selectedClusterId) > 0 && strlen(m_state.selectedPatternType) > 0) {
            NeuralSingularityEngine::TriggerPattern(m_state.selectedClusterId, m_state.selectedPatternType);
            m_state.selectedPatternType[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Patterns:");
    auto patterns = NeuralSingularityEngine::GetAllPatterns();
    if (ImGui::BeginTable("PatternsTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Cluster");
        ImGui::TableSetupColumn("Intensity");
        ImGui::TableSetupColumn("Duration");
        ImGui::TableHeadersRow();
        for (const auto& pattern : patterns) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", pattern.patternId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", pattern.patternType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", pattern.clusterId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", pattern.intensity);
            ImGui::TableNextColumn(); ImGui::Text("%.1f", pattern.duration);
        }
        ImGui::EndTable();
    }
}

void NeuralSingularityPanel::RenderPlasticityZonesTab() {
    ImGui::Text("Create Plasticity Zone:");
    ImGui::InputText("Zone Name", m_state.newZoneName, sizeof(m_state.newZoneName));
    if (ImGui::Button("Create")) {
        if (strlen(m_state.newZoneName) > 0) {
            NeuralSingularityEngine::CreatePlasticityZone(m_state.newZoneName);
            m_state.newZoneName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Plasticity Zones:");
    auto zones = NeuralSingularityEngine::GetAllZones();
    if (ImGui::BeginTable("ZonesTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Adaptability");
        ImGui::TableSetupColumn("Learning Rate");
        ImGui::TableSetupColumn("Memories");
        ImGui::TableHeadersRow();
        for (const auto& zone : zones) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", zone.zoneId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", zone.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", zone.adaptability);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", zone.learningRate);
            ImGui::TableNextColumn(); ImGui::Text("%zu", zone.memoryTraces.size());
        }
        ImGui::EndTable();
    }
}

void NeuralSingularityPanel::RenderCognitiveResonancesTab() {
    ImGui::Text("Active Cognitive Resonances:");
    auto resonances = NeuralSingularityEngine::GetAllResonances();
    if (ImGui::BeginTable("ResonancesTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Target");
        ImGui::TableSetupColumn("Coherence");
        ImGui::TableSetupColumn("Harmony");
        ImGui::TableHeadersRow();
        for (const auto& resonance : resonances) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", resonance.resonanceId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", resonance.sourcePattern.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", resonance.targetPattern.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", resonance.coherence);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", resonance.harmony);
        }
        ImGui::EndTable();
    }
}

void NeuralSingularityPanel::RenderMetricsTab() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    ImGui::Text("Neural Metrics:");
    if (m_currentMetrics.contains("clusterCount")) {
        ImGui::Text("Neural Clusters: %d", m_currentMetrics["clusterCount"].get<int>());
        ImGui::Text("Synaptic Pathways: %d", m_currentMetrics["pathwayCount"].get<int>());
        ImGui::Text("Activation Patterns: %d", m_currentMetrics["patternCount"].get<int>());
        ImGui::Text("Plasticity Zones: %d", m_currentMetrics["zoneCount"].get<int>());
        ImGui::Text("Cognitive Resonances: %d", m_currentMetrics["resonanceCount"].get<int>());
        ImGui::Separator();
        ImGui::Text("Total Activation: %.3f", m_currentMetrics["totalActivation"].get<float>());
        ImGui::Text("Average Plasticity: %.3f", m_currentMetrics["averagePlasticity"].get<float>());
        ImGui::Text("Active Patterns: %d", m_currentMetrics["activePatterns"].get<int>());
        ImGui::Text("Tick Count: %lld", m_currentMetrics["tickCount"].get<int64_t>());
    }
}

void NeuralSingularityPanel::RenderEventLogTab() {
    ImGui::Text("Recent Neural Events:");
    ImGui::BeginChild("EventLog", ImVec2(0, 400), true);
    for (const auto& event : m_state.eventLog) {
        ImGui::Text("%s", event.c_str());
    }
    ImGui::EndChild();
    if (ImGui::Button("Clear Log")) {
        m_state.eventLog.clear();
    }
}

void NeuralSingularityPanel::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    m_currentMetrics = NeuralSingularityEngine::GetNeuralMetrics();
}

} // namespace Neural
