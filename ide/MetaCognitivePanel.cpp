#include "ide/MetaCognitivePanel.hpp"
#include "metacognitive/MetaCognitiveEngine.hpp"
#include "metacognitive/MetaCognitiveLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace MetaCognitive {

MetaCognitivePanel::MetaCognitivePanel()
    : m_visible(false)
    , m_initialized(false)
    , m_loop(nullptr)
{
    m_currentMetrics = nlohmann::json::object();
}

MetaCognitivePanel::~MetaCognitivePanel() {
    Shutdown();
}

void MetaCognitivePanel::Initialize() {
    if (m_initialized) return;
    MetaCognitiveEngine::Init();
    m_loop = new MetaCognitiveLoop();
    m_loop->RegisterTickCallback([this]() { OnTick(); });
    m_loop->RegisterMetaCognitiveCallback([this](const std::string& event) { OnMetaCognitiveEvent(event); });
    m_initialized = true;
}

void MetaCognitivePanel::Shutdown() {
    if (!m_initialized) return;
    if (m_loop) {
        m_loop->Stop();
        delete m_loop;
        m_loop = nullptr;
    }
    MetaCognitiveEngine::Shutdown();
    m_initialized = false;
}

void MetaCognitivePanel::Render(const char* title) {
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

        if (ImGui::BeginTabBar("MetaCognitiveTabs")) {
            if (m_state.showReflectionPools && ImGui::BeginTabItem("Reflection Pools")) {
                RenderReflectionPoolsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showIntrospectionModules && ImGui::BeginTabItem("Introspection Modules")) {
                RenderIntrospectionModulesTab();
                ImGui::EndTabItem();
            }
            if (m_state.showSelfModels && ImGui::BeginTabItem("Self Models")) {
                RenderSelfModelsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showAwarenessMonitors && ImGui::BeginTabItem("Awareness Monitors")) {
                RenderAwarenessMonitorsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showCognitiveBiases && ImGui::BeginTabItem("Cognitive Biases")) {
                RenderCognitiveBiasesTab();
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

bool MetaCognitivePanel::IsVisible() const {
    return m_visible;
}

void MetaCognitivePanel::SetVisible(bool visible) {
    m_visible = visible;
}

void MetaCognitivePanel::ToggleVisibility() {
    m_visible = !m_visible;
}

void MetaCognitivePanel::OnTick() {
    UpdateMetrics();
}

void MetaCognitivePanel::OnMetaCognitiveEvent(const std::string& event) {
    m_state.eventLog.push_back(event);
    if (m_state.eventLog.size() > 100) {
        m_state.eventLog.erase(m_state.eventLog.begin());
    }
}

MetaCognitivePanelState& MetaCognitivePanel::GetState() {
    return m_state;
}

void MetaCognitivePanel::RenderReflectionPoolsTab() {
    ImGui::Text("Create Reflection Pool:");
    ImGui::InputText("Pool Name", m_state.newPoolName, sizeof(m_state.newPoolName));
    if (ImGui::Button("Create")) {
        if (strlen(m_state.newPoolName) > 0) {
            MetaCognitiveEngine::CreateReflectionPool(m_state.newPoolName);
            m_state.newPoolName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Reflection Pools:");
    auto pools = MetaCognitiveEngine::GetAllPools();
    if (ImGui::BeginTable("PoolsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Depth");
        ImGui::TableSetupColumn("Clarity");
        ImGui::TableHeadersRow();
        for (const auto& pool : pools) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", pool.poolId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", pool.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", pool.depth);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", pool.clarity);
        }
        ImGui::EndTable();
    }
}

void MetaCognitivePanel::RenderIntrospectionModulesTab() {
    ImGui::Text("Install Introspection Module:");
    ImGui::InputText("Module Name", m_state.newModuleName, sizeof(m_state.newModuleName));
    ImGui::InputText("Target System", m_state.selectedTarget, sizeof(m_state.selectedTarget));
    if (ImGui::Button("Install")) {
        if (strlen(m_state.newModuleName) > 0 && strlen(m_state.selectedTarget) > 0) {
            MetaCognitiveEngine::InstallIntrospectionModule(m_state.newModuleName, m_state.selectedTarget);
            m_state.newModuleName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Installed Introspection Modules:");
    auto modules = MetaCognitiveEngine::GetAllModules();
    if (ImGui::BeginTable("ModulesTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Target");
        ImGui::TableSetupColumn("Accuracy");
        ImGui::TableSetupColumn("Active");
        ImGui::TableHeadersRow();
        for (const auto& module : modules) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", module.moduleId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", module.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", module.targetSystem.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", module.accuracy);
            ImGui::TableNextColumn(); ImGui::Text("%s", module.isActive ? "Yes" : "No");
        }
        ImGui::EndTable();
    }
}

void MetaCognitivePanel::RenderSelfModelsTab() {
    ImGui::Text("Construct Self Model:");
    ImGui::InputText("Model Name", m_state.newModelName, sizeof(m_state.newModelName));
    if (ImGui::Button("Construct")) {
        if (strlen(m_state.newModelName) > 0) {
            MetaCognitiveEngine::ConstructSelfModel(m_state.newModelName);
            m_state.newModelName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Constructed Self Models:");
    auto models = MetaCognitiveEngine::GetAllModels();
    if (ImGui::BeginTable("ModelsTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Fidelity");
        ImGui::TableSetupColumn("Completeness");
        ImGui::TableSetupColumn("Consistency");
        ImGui::TableHeadersRow();
        for (const auto& model : models) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", model.modelId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", model.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", model.fidelity);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", model.completeness);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", model.consistency);
        }
        ImGui::EndTable();
    }
}

void MetaCognitivePanel::RenderAwarenessMonitorsTab() {
    ImGui::Text("Active Awareness Monitors:");
    auto monitors = MetaCognitiveEngine::GetAllMonitors();
    if (ImGui::BeginTable("MonitorsTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Level");
        ImGui::TableSetupColumn("Monitoring");
        ImGui::TableHeadersRow();
        for (const auto& monitor : monitors) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", monitor.monitorId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", monitor.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", monitor.awarenessType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", monitor.level);
            ImGui::TableNextColumn(); ImGui::Text("%s", monitor.isMonitoring ? "Yes" : "No");
        }
        ImGui::EndTable();
    }
}

void MetaCognitivePanel::RenderCognitiveBiasesTab() {
    ImGui::Text("Identify Cognitive Bias:");
    ImGui::InputText("Bias Name", m_state.selectedTarget, sizeof(m_state.selectedTarget));
    ImGui::InputText("Bias Type", m_state.selectedType, sizeof(m_state.selectedType));
    if (ImGui::Button("Identify")) {
        if (strlen(m_state.selectedTarget) > 0 && strlen(m_state.selectedType) > 0) {
            MetaCognitiveEngine::IdentifyBias(m_state.selectedTarget, m_state.selectedType);
            m_state.selectedTarget[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Identified Cognitive Biases:");
    auto biases = MetaCognitiveEngine::GetAllBiases();
    if (ImGui::BeginTable("BiasesTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Strength");
        ImGui::TableSetupColumn("Mitigated");
        ImGui::TableHeadersRow();
        for (const auto& bias : biases) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", bias.biasId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", bias.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", bias.biasType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", bias.strength);
            ImGui::TableNextColumn(); ImGui::Text("%s", bias.isMitigated ? "Yes" : "No");
        }
        ImGui::EndTable();
    }
}

void MetaCognitivePanel::RenderMetricsTab() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    ImGui::Text("Meta-Cognitive Metrics:");
    if (m_currentMetrics.contains("poolCount")) {
        ImGui::Text("Reflection Pools: %d", m_currentMetrics["poolCount"].get<int>());
        ImGui::Text("Introspection Modules: %d", m_currentMetrics["moduleCount"].get<int>());
        ImGui::Text("Self Models: %d", m_currentMetrics["modelCount"].get<int>());
        ImGui::Text("Awareness Monitors: %d", m_currentMetrics["monitorCount"].get<int>());
        ImGui::Text("Cognitive Biases: %d", m_currentMetrics["biasCount"].get<int>());
        ImGui::Separator();
        ImGui::Text("Average Reflection Depth: %.3f", m_currentMetrics["averageReflectionDepth"].get<float>());
        ImGui::Text("Total Introspection Accuracy: %.3f", m_currentMetrics["totalIntrospectionAccuracy"].get<float>());
        ImGui::Text("Active Monitors: %d", m_currentMetrics["activeMonitors"].get<int>());
        ImGui::Text("Mitigated Biases: %d", m_currentMetrics["mitigatedBiases"].get<int>());
        ImGui::Text("Tick Count: %lld", m_currentMetrics["tickCount"].get<int64_t>());
    }
}

void MetaCognitivePanel::RenderEventLogTab() {
    ImGui::Text("Recent Meta-Cognitive Events:");
    ImGui::BeginChild("EventLog", ImVec2(0, 400), true);
    for (const auto& event : m_state.eventLog) {
        ImGui::Text("%s", event.c_str());
    }
    ImGui::EndChild();
    if (ImGui::Button("Clear Log")) {
        m_state.eventLog.clear();
    }
}

void MetaCognitivePanel::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    m_currentMetrics = MetaCognitiveEngine::GetMetaCognitiveMetrics();
}

} // namespace MetaCognitive
