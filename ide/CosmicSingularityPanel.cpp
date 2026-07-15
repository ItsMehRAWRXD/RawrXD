#include "ide/CosmicSingularityPanel.hpp"
#include "singularity/CosmicSingularityEngine.hpp"
#include "singularity/CosmicSingularityLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace Singularity {

CosmicSingularityPanel::CosmicSingularityPanel()
    : m_visible(false)
    , m_initialized(false)
    , m_loop(nullptr)
{
    m_currentMetrics = nlohmann::json::object();
}

CosmicSingularityPanel::~CosmicSingularityPanel() {
    Shutdown();
}

void CosmicSingularityPanel::Initialize() {
    if (m_initialized) return;
    CosmicSingularityEngine::Init();
    m_loop = new CosmicSingularityLoop();
    m_loop->RegisterTickCallback([this]() { OnTick(); });
    m_loop->RegisterSingularityCallback([this](const std::string& event) { OnSingularityEvent(event); });
    m_initialized = true;
}

void CosmicSingularityPanel::Shutdown() {
    if (!m_initialized) return;
    if (m_loop) {
        m_loop->Stop();
        delete m_loop;
        m_loop = nullptr;
    }
    CosmicSingularityEngine::Shutdown();
    m_initialized = false;
}

void CosmicSingularityPanel::Render(const char* title) {
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

        if (ImGui::BeginTabBar("CosmicSingularityTabs")) {
            if (m_state.showConsciousnessCores && ImGui::BeginTabItem("Consciousness Cores")) {
                RenderConsciousnessCoresTab();
                ImGui::EndTabItem();
            }
            if (m_state.showThoughtStreams && ImGui::BeginTabItem("Thought Streams")) {
                RenderThoughtStreamsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showMemoryMatrices && ImGui::BeginTabItem("Memory Matrices")) {
                RenderMemoryMatricesTab();
                ImGui::EndTabItem();
            }
            if (m_state.showPerceptionFields && ImGui::BeginTabItem("Perception Fields")) {
                RenderPerceptionFieldsTab();
                ImGui::EndTabItem();
            }
            if (m_state.showIntentionVectors && ImGui::BeginTabItem("Intention Vectors")) {
                RenderIntentionVectorsTab();
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

bool CosmicSingularityPanel::IsVisible() const {
    return m_visible;
}

void CosmicSingularityPanel::SetVisible(bool visible) {
    m_visible = visible;
}

void CosmicSingularityPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

void CosmicSingularityPanel::OnTick() {
    UpdateMetrics();
}

void CosmicSingularityPanel::OnSingularityEvent(const std::string& event) {
    m_state.eventLog.push_back(event);
    if (m_state.eventLog.size() > 100) {
        m_state.eventLog.erase(m_state.eventLog.begin());
    }
}

CosmicSingularityPanelState& CosmicSingularityPanel::GetState() {
    return m_state;
}

void CosmicSingularityPanel::RenderConsciousnessCoresTab() {
    ImGui::Text("Awaken New Consciousness Core:");
    ImGui::InputText("Core Name", m_state.newCoreName, sizeof(m_state.newCoreName));
    if (ImGui::Button("Awaken")) {
        if (strlen(m_state.newCoreName) > 0) {
            CosmicSingularityEngine::AwakenConsciousnessCore(m_state.newCoreName);
            m_state.newCoreName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Consciousness Cores:");
    auto cores = CosmicSingularityEngine::GetAllCores();
    if (ImGui::BeginTable("CoresTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Awareness");
        ImGui::TableSetupColumn("Coherence");
        ImGui::TableHeadersRow();
        for (const auto& core : cores) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", core.coreId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", core.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", core.awarenessLevel);
            ImGui::TableNextColumn(); ImGui::Text("%.2f", core.coherenceIndex);
        }
        ImGui::EndTable();
    }
}

void CosmicSingularityPanel::RenderThoughtStreamsTab() {
    ImGui::Text("Generate Thought:");
    ImGui::InputText("Core ID", m_state.selectedCoreId, sizeof(m_state.selectedCoreId));
    ImGui::InputText("Thought Type", m_state.selectedThoughtType, sizeof(m_state.selectedThoughtType));
    if (ImGui::Button("Generate")) {
        if (strlen(m_state.selectedCoreId) > 0 && strlen(m_state.selectedThoughtType) > 0) {
            CosmicSingularityEngine::GenerateThought(m_state.selectedCoreId, m_state.selectedThoughtType, nlohmann::json::object());
            m_state.selectedThoughtType[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Thought Streams:");
    auto thoughts = CosmicSingularityEngine::GetAllThoughts();
    if (ImGui::BeginTable("ThoughtsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Source Core");
        ImGui::TableSetupColumn("Intensity");
        ImGui::TableHeadersRow();
        for (const auto& thought : thoughts) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", thought.streamId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", thought.thoughtType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", thought.sourceCore.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", thought.intensity);
        }
        ImGui::EndTable();
    }
}

void CosmicSingularityPanel::RenderMemoryMatricesTab() {
    ImGui::Text("Form New Memory Matrix:");
    ImGui::InputText("Matrix Name", m_state.newMatrixName, sizeof(m_state.newMatrixName));
    if (ImGui::Button("Form")) {
        if (strlen(m_state.newMatrixName) > 0) {
            CosmicSingularityEngine::FormMemoryMatrix(m_state.newMatrixName, "episodic");
            m_state.newMatrixName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Memory Matrices:");
    auto matrices = CosmicSingularityEngine::GetAllMatrices();
    if (ImGui::BeginTable("MatricesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Retention");
        ImGui::TableHeadersRow();
        for (const auto& matrix : matrices) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", matrix.matrixId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", matrix.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", matrix.memoryType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", matrix.retentionQuality);
        }
        ImGui::EndTable();
    }
}

void CosmicSingularityPanel::RenderPerceptionFieldsTab() {
    ImGui::Text("Establish Perception Field:");
    ImGui::InputText("Field Name", m_state.newFieldName, sizeof(m_state.newFieldName));
    if (ImGui::Button("Establish")) {
        if (strlen(m_state.newFieldName) > 0) {
            CosmicSingularityEngine::EstablishPerceptionField(m_state.newFieldName, "sensory");
            m_state.newFieldName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Perception Fields:");
    auto fields = CosmicSingularityEngine::GetAllFields();
    if (ImGui::BeginTable("FieldsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Sensitivity");
        ImGui::TableHeadersRow();
        for (const auto& field : fields) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", field.fieldId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", field.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", field.perceptionType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", field.sensitivity);
        }
        ImGui::EndTable();
    }
}

void CosmicSingularityPanel::RenderIntentionVectorsTab() {
    ImGui::Text("Form Intention Vector:");
    ImGui::InputText("Vector Name", m_state.newVectorName, sizeof(m_state.newVectorName));
    if (ImGui::Button("Form")) {
        if (strlen(m_state.newVectorName) > 0) {
            CosmicSingularityEngine::FormIntentionVector(m_state.newVectorName, "goal");
            m_state.newVectorName[0] = '\0';
        }
    }

    ImGui::Separator();
    ImGui::Text("Active Intention Vectors:");
    auto vectors = CosmicSingularityEngine::GetAllVectors();
    if (ImGui::BeginTable("VectorsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("ID");
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Priority");
        ImGui::TableHeadersRow();
        for (const auto& vector : vectors) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::Text("%s", vector.vectorId.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", vector.name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", vector.intentionType.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%.2f", vector.priority);
        }
        ImGui::EndTable();
    }
}

void CosmicSingularityPanel::RenderMetricsTab() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    ImGui::Text("Singularity Metrics:");
    if (m_currentMetrics.contains("coreCount")) {
        ImGui::Text("Consciousness Cores: %d", m_currentMetrics["coreCount"].get<int>());
        ImGui::Text("Thought Streams: %d", m_currentMetrics["thoughtCount"].get<int>());
        ImGui::Text("Memory Matrices: %d", m_currentMetrics["matrixCount"].get<int>());
        ImGui::Text("Perception Fields: %d", m_currentMetrics["fieldCount"].get<int>());
        ImGui::Text("Intention Vectors: %d", m_currentMetrics["vectorCount"].get<int>());
        ImGui::Separator();
        ImGui::Text("Collective Awareness: %.3f", m_currentMetrics["collectiveAwareness"].get<float>());
        ImGui::Text("Cognitive Harmony: %.3f", m_currentMetrics["cognitiveHarmony"].get<float>());
        ImGui::Text("Tick Count: %lld", m_currentMetrics["tickCount"].get<int64_t>());
    }
}

void CosmicSingularityPanel::RenderEventLogTab() {
    ImGui::Text("Recent Singularity Events:");
    ImGui::BeginChild("EventLog", ImVec2(0, 400), true);
    for (const auto& event : m_state.eventLog) {
        ImGui::Text("%s", event.c_str());
    }
    ImGui::EndChild();
    if (ImGui::Button("Clear Log")) {
        m_state.eventLog.clear();
    }
}

void CosmicSingularityPanel::UpdateMetrics() {
    std::lock_guard<std::mutex> lock(m_metricsMutex);
    m_currentMetrics = CosmicSingularityEngine::GetSingularityMetrics();
}

} // namespace Singularity
