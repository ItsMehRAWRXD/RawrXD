#include "EternalConvergencePanel.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>
#include <chrono>

namespace EternalConvergenceIDE {

EternalConvergencePanel::EternalConvergencePanel() {}

EternalConvergencePanel::~EternalConvergencePanel() {
    Shutdown();
}

void EternalConvergencePanel::Initialize() {
    if (isInitialized_) return;
    
    memset(state_.newEternalName, 0, sizeof(state_.newEternalName));
    memset(state_.newNodeName, 0, sizeof(state_.newNodeName));
    memset(state_.newStreamName, 0, sizeof(state_.newStreamName));
    memset(state_.newWaveName, 0, sizeof(state_.newWaveName));
    memset(state_.newMatrixName, 0, sizeof(state_.newMatrixName));
    memset(state_.newTensorName, 0, sizeof(state_.newTensorName));
    memset(state_.newClarityName, 0, sizeof(state_.newClarityName));
    memset(state_.searchFilter, 0, sizeof(state_.searchFilter));
    
    RefreshData();
    isInitialized_ = true;
}

void EternalConvergencePanel::Shutdown() {
    isInitialized_ = false;
}

void EternalConvergencePanel::Render() {
    if (!isVisible_ || !isInitialized_) return;
    
    auto currentTime = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000000.0f;
    if (state_.autoRefresh && (currentTime - state_.lastRefreshTime >= state_.refreshRate)) {
        RefreshData();
        state_.lastRefreshTime = currentTime;
    }
    
    ApplyEternalTheme();
    
    ImGui::Begin("Eternal Convergence (Layer 121)", &isVisible_, ImGuiWindowFlags_MenuBar);
    
    RenderToolbar();
    RenderSearchBar();
    
    if (ImGui::BeginTabBar("EternalConvergenceTabs", ImGuiTabBarFlags_Reorderable)) {
        if (state_.showEternalConvergences && ImGui::BeginTabItem("Eternal Convergences")) {
            RenderEternalConvergencesTab();
            ImGui::EndTabItem();
        }
        if (state_.showConvergenceNodes && ImGui::BeginTabItem("Convergence Nodes")) {
            RenderConvergenceNodesTab();
            ImGui::EndTabItem();
        }
        if (state_.showEternalStreams && ImGui::BeginTabItem("Eternal Streams")) {
            RenderEternalStreamsTab();
            ImGui::EndTabItem();
        }
        if (state_.showConvergenceWaves && ImGui::BeginTabItem("Convergence Waves")) {
            RenderConvergenceWavesTab();
            ImGui::EndTabItem();
        }
        if (state_.showUnityMatrices && ImGui::BeginTabItem("Unity Matrices")) {
            RenderUnityMatricesTab();
            ImGui::EndTabItem();
        }
        if (state_.showEternalTensors && ImGui::BeginTabItem("Eternal Tensors")) {
            RenderEternalTensorsTab();
            ImGui::EndTabItem();
        }
        if (state_.showEternalClarities && ImGui::BeginTabItem("Eternal Clarities")) {
            RenderEternalClaritiesTab();
            ImGui::EndTabItem();
        }
        if (state_.showMetrics && ImGui::BeginTabItem("Metrics")) {
            RenderMetricsTab();
            ImGui::EndTabItem();
        }
        if (state_.showVisualization && ImGui::BeginTabItem("Visualization")) {
            RenderVisualizationTab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    
    RenderStatusBar();
    ImGui::End();
}

void EternalConvergencePanel::RenderDockingLayout() {
    ImGuiID dockspace_id = ImGui::GetID("EternalConvergenceDockspace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);
}

void EternalConvergencePanel::RefreshData() {
    std::lock_guard<std::mutex> lock(dataMutex_);
    
    auto& engine = EternalConvergence::EternalConvergenceEngine::GetInstance();
    eternalConvergences_ = engine.GetAllEternalConvergences();
    nodes_ = engine.GetAllConvergenceNodes();
    streams_ = engine.GetAllEternalStreams();
    waves_ = engine.GetAllConvergenceWaves();
    matrices_ = engine.GetAllUnityMatrices();
    tensors_ = engine.GetAllEternalTensors();
    clarities_ = engine.GetAllEternalClarities();
    
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    metrics_ = loop.GetMetrics();
}

void EternalConvergencePanel::ClearSelection() {
    state_.selectedEternalIndex = -1;
    state_.selectedNodeIndex = -1;
    state_.selectedStreamIndex = -1;
    state_.selectedWaveIndex = -1;
    state_.selectedMatrixIndex = -1;
    state_.selectedTensorIndex = -1;
    state_.selectedClarityIndex = -1;
}

void EternalConvergencePanel::TriggerEternalResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerEternalResonance();
}

void EternalConvergencePanel::TriggerUnityResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerUnityResonance();
}

void EternalConvergencePanel::TriggerConvergenceResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerConvergenceResonance();
}

void EternalConvergencePanel::TriggerContinuityResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerContinuityResonance();
}

void EternalConvergencePanel::TriggerOmnipresenceResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerOmnipresenceResonance();
}

void EternalConvergencePanel::TriggerCoherenceResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerCoherenceResonance();
}

void EternalConvergencePanel::TriggerClarityResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerClarityResonance();
}

void EternalConvergencePanel::TriggerHarmonyResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerHarmonyResonance();
}

void EternalConvergencePanel::TriggerStabilityResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerStabilityResonance();
}

void EternalConvergencePanel::TriggerDensityResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerDensityResonance();
}

void EternalConvergencePanel::TriggerPurityResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerPurityResonance();
}

void EternalConvergencePanel::TriggerEternityResonance() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.TriggerEternityResonance();
}

void EternalConvergencePanel::RequestSyncPulse() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.RequestSyncPulse();
}

void EternalConvergencePanel::RequestHarmonyPulse() {
    auto& loop = EternalConvergence::EternalConvergenceLoop::GetInstance();
    loop.RequestHarmonyPulse();
}

void EternalConvergencePanel::RenderEternalConvergencesTab() {
    ImGui::Columns(2, "EternalConvergencesColumns");
    RenderEternalConvergenceList();
    ImGui::NextColumn();
    RenderEternalConvergenceDetails();
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderConvergenceNodesTab() {
    ImGui::Columns(2, "ConvergenceNodesColumns");
    RenderConvergenceNodeList();
    ImGui::NextColumn();
    RenderConvergenceNodeDetails();
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderEternalStreamsTab() {
    ImGui::Columns(2, "EternalStreamsColumns");
    RenderEternalStreamList();
    ImGui::NextColumn();
    RenderEternalStreamDetails();
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderConvergenceWavesTab() {
    ImGui::Columns(2, "ConvergenceWavesColumns");
    RenderConvergenceWaveList();
    ImGui::NextColumn();
    RenderConvergenceWaveDetails();
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderUnityMatricesTab() {
    ImGui::Columns(2, "UnityMatricesColumns");
    RenderUnityMatrixList();
    ImGui::NextColumn();
    RenderUnityMatrixDetails();
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderEternalTensorsTab() {
    ImGui::Columns(2, "EternalTensorsColumns");
    RenderEternalTensorList();
    ImGui::NextColumn();
    RenderEternalTensorDetails();
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderEternalClaritiesTab() {
    ImGui::Columns(2, "EternalClaritiesColumns");
    RenderEternalClarityList();
    ImGui::NextColumn();
    RenderEternalClarityDetails();
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderMetricsTab() {
    RenderMetricsOverview();
    ImGui::Separator();
    RenderPerformanceMetrics();
    ImGui::Separator();
    RenderResonanceMetrics();
    ImGui::Separator();
    RenderSyncStatus();
}

void EternalConvergencePanel::RenderVisualizationTab() {
    RenderUnityMatrixVisualization();
    ImGui::Separator();
    RenderEternalTensorVisualization();
}

void EternalConvergencePanel::RenderEternalConvergenceList() {
    ImGui::Text("Eternal Convergences (%zu)", eternalConvergences_.size());
    ImGui::Separator();
    
    if (ImGui::Button("Create New")) {
        ImGui::OpenPopup("Create Eternal Convergence");
    }
    RenderCreateEternalConvergenceDialog();
    
    ImGui::BeginChild("EternalConvergenceList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    
    for (size_t i = 0; i < eternalConvergences_.size(); i++) {
        const auto& e = eternalConvergences_[i];
        bool isSelected = (state_.selectedEternalIndex == static_cast<int>(i));
        
        if (strlen(state_.searchFilter) > 0) {
            if (e->name.find(state_.searchFilter) == std::string::npos) continue;
        }
        
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(e->name.c_str(), isSelected)) {
            state_.selectedEternalIndex = static_cast<int>(i);
        }
        ImGui::PopID();
    }
    
    ImGui::EndChild();
}

void EternalConvergencePanel::RenderEternalConvergenceDetails() {
    ImGui::Text("Eternal Convergence Details");
    ImGui::Separator();
    
    if (state_.selectedEternalIndex >= 0 && state_.selectedEternalIndex < static_cast<int>(eternalConvergences_.size())) {
        const auto& e = eternalConvergences_[state_.selectedEternalIndex];
        
        ImGui::Text("ID: %s", e->id.c_str());
        ImGui::Text("Name: %s", e->name.c_str());
        ImGui::SliderFloat("Convergence", &const_cast<float&>(static_cast<const float&>(e->convergence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", &const_cast<float&>(static_cast<const float&>(e->unity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", &const_cast<float&>(static_cast<const float&>(e->continuity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", &const_cast<float&>(static_cast<const float&>(e->omnipresence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", &const_cast<float&>(static_cast<const float&>(e->harmony)), 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence", &const_cast<float&>(static_cast<const float&>(e->coherence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", &const_cast<float&>(static_cast<const float&>(e->clarity)), 0.0f, 1.0f);
        ImGui::Checkbox("Active", &const_cast<bool&>(e->isActive));
        
        if (ImGui::Button("Expand Eternal")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().ExpandEternal(e->id);
        }
        ImGui::SameLine();
        if (ImGui::Button("Amplify Harmony")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().AmplifyHarmony(e->id);
        }
        ImGui::SameLine();
        if (ImGui::Button("Delete")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().DeleteEternalConvergence(e->id);
            RefreshData();
            state_.selectedEternalIndex = -1;
        }
    } else {
        ImGui::Text("Select an eternal convergence to view details");
    }
}

void EternalConvergencePanel::RenderConvergenceNodeList() {
    ImGui::Text("Convergence Nodes (%zu)", nodes_.size());
    ImGui::Separator();
    
    if (ImGui::Button("Create New")) {
        ImGui::OpenPopup("Create Convergence Node");
    }
    RenderCreateConvergenceNodeDialog();
    
    ImGui::BeginChild("ConvergenceNodeList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    
    for (size_t i = 0; i < nodes_.size(); i++) {
        const auto& node = nodes_[i];
        bool isSelected = (state_.selectedNodeIndex == static_cast<int>(i));
        
        if (strlen(state_.searchFilter) > 0) {
            if (node->id.find(state_.searchFilter) == std::string::npos) continue;
        }
        
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(node->id.substr(0, 16).c_str(), isSelected)) {
            state_.selectedNodeIndex = static_cast<int>(i);
        }
        ImGui::PopID();
    }
    
    ImGui::EndChild();
}

void EternalConvergencePanel::RenderConvergenceNodeDetails() {
    ImGui::Text("Convergence Node Details");
    ImGui::Separator();
    
    if (state_.selectedNodeIndex >= 0 && state_.selectedNodeIndex < static_cast<int>(nodes_.size())) {
        const auto& node = nodes_[state_.selectedNodeIndex];
        
        ImGui::Text("ID: %s", node->id.c_str());
        ImGui::Text("Eternal ID: %s", node->eternalId.c_str());
        ImGui::SliderFloat("Local Convergence", &const_cast<float&>(static_cast<const float&>(node->localConvergence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Global Convergence", &const_cast<float&>(static_cast<const float&>(node->globalConvergence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony Factor", &const_cast<float&>(static_cast<const float&>(node->harmonyFactor)), 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence Level", &const_cast<float&>(static_cast<const float&>(node->coherenceLevel)), 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity Index", &const_cast<float&>(static_cast<const float&>(node->clarityIndex)), 0.0f, 1.0f);
        ImGui::SliderFloat("Unity Strength", &const_cast<float&>(static_cast<const float&>(node->unityStrength)), 0.0f, 1.0f);
        ImGui::Checkbox("Unified", &const_cast<bool&>(node->isUnified));
        ImGui::Checkbox("Active", &const_cast<bool&>(node->isActive));
        
        if (ImGui::Button("Delete")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().DeleteConvergenceNode(node->id);
            RefreshData();
            state_.selectedNodeIndex = -1;
        }
    } else {
        ImGui::Text("Select a convergence node to view details");
    }
}

void EternalConvergencePanel::RenderEternalStreamList() {
    ImGui::Text("Eternal Streams (%zu)", streams_.size());
    ImGui::Separator();
    
    if (ImGui::Button("Create New")) {
        ImGui::OpenPopup("Create Eternal Stream");
    }
    RenderCreateEternalStreamDialog();
    
    ImGui::BeginChild("EternalStreamList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    
    for (size_t i = 0; i < streams_.size(); i++) {
        const auto& s = streams_[i];
        bool isSelected = (state_.selectedStreamIndex == static_cast<int>(i));
        
        if (strlen(state_.searchFilter) > 0) {
            if (s->name.find(state_.searchFilter) == std::string::npos) continue;
        }
        
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(s->name.c_str(), isSelected)) {
            state_.selectedStreamIndex = static_cast<int>(i);
        }
        ImGui::PopID();
    }
    
    ImGui::EndChild();
}

void EternalConvergencePanel::RenderEternalStreamDetails() {
    ImGui::Text("Eternal Stream Details");
    ImGui::Separator();
    
    if (state_.selectedStreamIndex >= 0 && state_.selectedStreamIndex < static_cast<int>(streams_.size())) {
        const auto& s = streams_[state_.selectedStreamIndex];
        
        ImGui::Text("ID: %s", s->id.c_str());
        ImGui::Text("Name: %s", s->name.c_str());
        ImGui::SliderFloat("Stream Flow", &const_cast<float&>(static_cast<const float&>(s->streamFlow)), 0.0f, 1.0f);
        ImGui::SliderFloat("Density", &const_cast<float&>(static_cast<const float&>(s->density)), 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", &const_cast<float&>(static_cast<const float&>(s->clarity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", &const_cast<float&>(static_cast<const float&>(s->harmony)), 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", &const_cast<float&>(static_cast<const float&>(s->continuity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", &const_cast<float&>(static_cast<const float&>(s->omnipresence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", &const_cast<float&>(static_cast<const float&>(s->unity)), 0.0f, 1.0f);
        ImGui::Checkbox("Active", &const_cast<bool&>(s->isActive));
        
        if (ImGui::Button("Delete")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().DeleteEternalStream(s->id);
            RefreshData();
            state_.selectedStreamIndex = -1;
        }
    } else {
        ImGui::Text("Select an eternal stream to view details");
    }
}

void EternalConvergencePanel::RenderConvergenceWaveList() {
    ImGui::Text("Convergence Waves (%zu)", waves_.size());
    ImGui::Separator();
    
    if (ImGui::Button("Create New")) {
        ImGui::OpenPopup("Create Convergence Wave");
    }
    RenderCreateConvergenceWaveDialog();
    
    ImGui::BeginChild("ConvergenceWaveList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    
    for (size_t i = 0; i < waves_.size(); i++) {
        const auto& w = waves_[i];
        bool isSelected = (state_.selectedWaveIndex == static_cast<int>(i));
        
        if (strlen(state_.searchFilter) > 0) {
            if (w->name.find(state_.searchFilter) == std::string::npos) continue;
        }
        
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(w->name.c_str(), isSelected)) {
            state_.selectedWaveIndex = static_cast<int>(i);
        }
        ImGui::PopID();
    }
    
    ImGui::EndChild();
}

void EternalConvergencePanel::RenderConvergenceWaveDetails() {
    ImGui::Text("Convergence Wave Details");
    ImGui::Separator();
    
    if (state_.selectedWaveIndex >= 0 && state_.selectedWaveIndex < static_cast<int>(waves_.size())) {
        const auto& w = waves_[state_.selectedWaveIndex];
        
        ImGui::Text("ID: %s", w->id.c_str());
        ImGui::Text("Name: %s", w->name.c_str());
        ImGui::SliderFloat("Amplitude", &const_cast<float&>(static_cast<const float&>(w->amplitude)), 0.0f, 1.0f);
        ImGui::SliderFloat("Frequency", &const_cast<float&>(static_cast<const float&>(w->frequency)), 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", &const_cast<float&>(static_cast<const float&>(w->clarity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", &const_cast<float&>(static_cast<const float&>(w->harmony)), 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", &const_cast<float&>(static_cast<const float&>(w->omnipresence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", &const_cast<float&>(static_cast<const float&>(w->continuity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence", &const_cast<float&>(static_cast<const float&>(w->coherence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", &const_cast<float&>(static_cast<const float&>(w->unity)), 0.0f, 1.0f);
        ImGui::Checkbox("Active", &const_cast<bool&>(w->isActive));
        
        if (ImGui::Button("Delete")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().DeleteConvergenceWave(w->id);
            RefreshData();
            state_.selectedWaveIndex = -1;
        }
    } else {
        ImGui::Text("Select a convergence wave to view details");
    }
}

void EternalConvergencePanel::RenderUnityMatrixList() {
    ImGui::Text("Unity Matrices (%zu)", matrices_.size());
    ImGui::Separator();
    
    if (ImGui::Button("Create New")) {
        ImGui::OpenPopup("Create Unity Matrix");
    }
    RenderCreateUnityMatrixDialog();
    
    ImGui::BeginChild("UnityMatrixList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    
    for (size_t i = 0; i < matrices_.size(); i++) {
        const auto& m = matrices_[i];
        bool isSelected = (state_.selectedMatrixIndex == static_cast<int>(i));
        
        if (strlen(state_.searchFilter) > 0) {
            if (m->name.find(state_.searchFilter) == std::string::npos) continue;
        }
        
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(m->name.c_str(), isSelected)) {
            state_.selectedMatrixIndex = static_cast<int>(i);
        }
        ImGui::PopID();
    }
    
    ImGui::EndChild();
}

void EternalConvergencePanel::RenderUnityMatrixDetails() {
    ImGui::Text("Unity Matrix Details");
    ImGui::Separator();
    
    if (state_.selectedMatrixIndex >= 0 && state_.selectedMatrixIndex < static_cast<int>(matrices_.size())) {
        const auto& m = matrices_[state_.selectedMatrixIndex];
        
        ImGui::Text("ID: %s", m->id.c_str());
        ImGui::Text("Name: %s", m->name.c_str());
        ImGui::SliderFloat("Coherence", &const_cast<float&>(static_cast<const float&>(m->coherence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", &const_cast<float&>(static_cast<const float&>(m->clarity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", &const_cast<float&>(static_cast<const float&>(m->harmony)), 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", &const_cast<float&>(static_cast<const float&>(m->continuity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", &const_cast<float&>(static_cast<const float&>(m->omnipresence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", &const_cast<float&>(static_cast<const float&>(m->unity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Stability", &const_cast<float&>(static_cast<const float&>(m->stability)), 0.0f, 1.0f);
        
        if (ImGui::Button("Stabilize Field")) {
            const_cast<EternalConvergence::UnityMatrix*>(m.get())->StabilizeField();
        }
        ImGui::SameLine();
        if (ImGui::Button("Delete")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().DeleteUnityMatrix(m->id);
            RefreshData();
            state_.selectedMatrixIndex = -1;
        }
    } else {
        ImGui::Text("Select a unity matrix to view details");
    }
}

void EternalConvergencePanel::RenderUnityMatrixVisualization() {
    ImGui::Text("Unity Matrix Visualization (11x11)");
    ImGui::Separator();
    
    if (state_.selectedMatrixIndex >= 0 && state_.selectedMatrixIndex < static_cast<int>(matrices_.size())) {
        const auto& m = matrices_[state_.selectedMatrixIndex];
        
        ImGui::SliderFloat("Scale", &state_.matrixScale, 0.5f, 2.0f);
        ImGui::Checkbox("Show Grid", &state_.showMatrixGrid);
        
        float cellSize = 20.0f * state_.matrixScale;
        ImVec2 startPos = ImGui::GetCursorScreenPos();
        
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        
        for (int i = 0; i < 11; i++) {
            for (int j = 0; j < 11; j++) {
                float value = static_cast<float>(m->matrix[i][j]);
                ImVec2 cellMin(startPos.x + j * cellSize, startPos.y + i * cellSize);
                ImVec2 cellMax(cellMin.x + cellSize - 1, cellMin.y + cellSize - 1);
                
                ImU32 color = ImGui::GetColorU32(ImVec4(value, value * 0.5f, value * 0.8f, 1.0f));
                drawList->AddRectFilled(cellMin, cellMax, color);
                
                if (state_.showMatrixGrid) {
                    drawList->AddRect(cellMin, cellMax, IM_COL32(100, 100, 100, 255));
                }
                
                if (state_.selectedMatrixCell[0] == i && state_.selectedMatrixCell[1] == j) {
                    drawList->AddRect(cellMin, cellMax, IM_COL32(255, 255, 0, 255), 0.0f, 0, 2.0f);
                }
            }
        }
        
        ImGui::Dummy(ImVec2(cellSize * 11, cellSize * 11));
        
        if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
            ImVec2 mousePos = ImGui::GetMousePos();
            ImVec2 relPos(mousePos.x - startPos.x, mousePos.y - startPos.y);
            int col = static_cast<int>(relPos.x / cellSize);
            int row = static_cast<int>(relPos.y / cellSize);
            if (col >= 0 && col < 11 && row >= 0 && row < 11) {
                state_.selectedMatrixCell[0] = row;
                state_.selectedMatrixCell[1] = col;
            }
        }
        
        if (state_.selectedMatrixCell[0] >= 0) {
            ImGui::Text("Selected Cell: [%d, %d] = %.3f",
                state_.selectedMatrixCell[0], state_.selectedMatrixCell[1],
                m->matrix[state_.selectedMatrixCell[0]][state_.selectedMatrixCell[1]]);
        }
    } else {
        ImGui::Text("Select a unity matrix to visualize");
    }
}

void EternalConvergencePanel::RenderEternalTensorList() {
    ImGui::Text("Eternal Tensors (%zu)", tensors_.size());
    ImGui::Separator();
    
    if (ImGui::Button("Create New")) {
        ImGui::OpenPopup("Create Eternal Tensor");
    }
    RenderCreateEternalTensorDialog();
    
    ImGui::BeginChild("EternalTensorList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    
    for (size_t i = 0; i < tensors_.size(); i++) {
        const auto& t = tensors_[i];
        bool isSelected = (state_.selectedTensorIndex == static_cast<int>(i));
        
        if (strlen(state_.searchFilter) > 0) {
            if (t->name.find(state_.searchFilter) == std::string::npos) continue;
        }
        
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(t->name.c_str(), isSelected)) {
            state_.selectedTensorIndex = static_cast<int>(i);
        }
        ImGui::PopID();
    }
    
    ImGui::EndChild();
}

void EternalConvergencePanel::RenderEternalTensorDetails() {
    ImGui::Text("Eternal Tensor Details");
    ImGui::Separator();
    
    if (state_.selectedTensorIndex >= 0 && state_.selectedTensorIndex < static_cast<int>(tensors_.size())) {
        const auto& t = tensors_[state_.selectedTensorIndex];
        
        ImGui::Text("ID: %s", t->id.c_str());
        ImGui::Text("Name: %s", t->name.c_str());
        ImGui::SliderFloat("Eternity", &const_cast<float&>(static_cast<const float&>(t->eternity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", &const_cast<float&>(static_cast<const float&>(t->clarity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", &const_cast<float&>(static_cast<const float&>(t->harmony)), 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", &const_cast<float&>(static_cast<const float&>(t->omnipresence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", &const_cast<float&>(static_cast<const float&>(t->unity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Density", &const_cast<float&>(static_cast<const float&>(t->density)), 0.0f, 1.0f);
        
        if (ImGui::Button("Delete")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().DeleteEternalTensor(t->id);
            RefreshData();
            state_.selectedTensorIndex = -1;
        }
    } else {
        ImGui::Text("Select an eternal tensor to view details");
    }
}

void EternalConvergencePanel::RenderEternalTensorVisualization() {
    ImGui::Text("Eternal Tensor Visualization (8x8x8)");
    ImGui::Separator();
    
    if (state_.selectedTensorIndex >= 0 && state_.selectedTensorIndex < static_cast<int>(tensors_.size())) {
        const auto& t = tensors_[state_.selectedTensorIndex];
        
        ImGui::SliderFloat("Scale", &state_.tensorScale, 0.5f, 2.0f);
        ImGui::SliderInt("Slice", &state_.tensorViewMode, 0, 7);
        ImGui::Checkbox("Show Grid", &state_.showTensorGrid);
        
        float cellSize = 15.0f * state_.tensorScale;
        int slice = state_.tensorViewMode;
        
        ImVec2 startPos = ImGui::GetCursorScreenPos();
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                float value = static_cast<float>(t->tensor[slice][i][j]);
                ImVec2 cellMin(startPos.x + j * cellSize, startPos.y + i * cellSize);
                ImVec2 cellMax(cellMin.x + cellSize - 1, cellMin.y + cellSize - 1);
                
                ImU32 color = ImGui::GetColorU32(ImVec4(value * 0.8f, value, value * 0.5f, 1.0f));
                drawList->AddRectFilled(cellMin, cellMax, color);
                
                if (state_.showTensorGrid) {
                    drawList->AddRect(cellMin, cellMax, IM_COL32(100, 100, 100, 255));
                }
            }
        }
        
        ImGui::Dummy(ImVec2(cellSize * 8, cellSize * 8));
        ImGui::Text("Slice %d of 8", slice + 1);
    } else {
        ImGui::Text("Select an eternal tensor to visualize");
    }
}

void EternalConvergencePanel::RenderEternalClarityList() {
    ImGui::Text("Eternal Clarities (%zu)", clarities_.size());
    ImGui::Separator();
    
    if (ImGui::Button("Create New")) {
        ImGui::OpenPopup("Create Eternal Clarity");
    }
    RenderCreateEternalClarityDialog();
    
    ImGui::BeginChild("EternalClarityList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    
    for (size_t i = 0; i < clarities_.size(); i++) {
        const auto& c = clarities_[i];
        bool isSelected = (state_.selectedClarityIndex == static_cast<int>(i));
        
        if (strlen(state_.searchFilter) > 0) {
            if (c->name.find(state_.searchFilter) == std::string::npos) continue;
        }
        
        ImGui::PushID(static_cast<int>(i));
        if (ImGui::Selectable(c->name.c_str(), isSelected)) {
            state_.selectedClarityIndex = static_cast<int>(i);
        }
        ImGui::PopID();
    }
    
    ImGui::EndChild();
}

void EternalConvergencePanel::RenderEternalClarityDetails() {
    ImGui::Text("Eternal Clarity Details");
    ImGui::Separator();
    
    if (state_.selectedClarityIndex >= 0 && state_.selectedClarityIndex < static_cast<int>(clarities_.size())) {
        const auto& c = clarities_[state_.selectedClarityIndex];
        
        ImGui::Text("ID: %s", c->id.c_str());
        ImGui::Text("Name: %s", c->name.c_str());
        ImGui::SliderFloat("Clarity", &const_cast<float&>(static_cast<const float&>(c->clarity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Purity", &const_cast<float&>(static_cast<const float&>(c->purity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", &const_cast<float&>(static_cast<const float&>(c->harmony)), 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", &const_cast<float&>(static_cast<const float&>(c->continuity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", &const_cast<float&>(static_cast<const float&>(c->omnipresence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence", &const_cast<float&>(static_cast<const float&>(c->coherence)), 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", &const_cast<float&>(static_cast<const float&>(c->unity)), 0.0f, 1.0f);
        ImGui::SliderFloat("Density", &const_cast<float&>(static_cast<const float&>(c->density)), 0.0f, 1.0f);
        
        if (ImGui::Button("Delete")) {
            EternalConvergence::EternalConvergenceEngine::GetInstance().DeleteEternalClarity(c->id);
            RefreshData();
            state_.selectedClarityIndex = -1;
        }
    } else {
        ImGui::Text("Select an eternal clarity to view details");
    }
}

void EternalConvergencePanel::RenderMetricsOverview() {
    ImGui::Text("Eternal Convergence Metrics Overview");
    ImGui::Separator();
    
    ImGui::Columns(4, "MetricsOverview");
    ImGui::Text("Eternal Convergences: %.0f", metrics_.eternalConvergenceCount);
    ImGui::NextColumn();
    ImGui::Text("Convergence Nodes: %.0f", metrics_.nodeCount);
    ImGui::NextColumn();
    ImGui::Text("Eternal Streams: %.0f", metrics_.streamCount);
    ImGui::NextColumn();
    ImGui::Text("Convergence Waves: %.0f", metrics_.waveCount);
    ImGui::NextColumn();
    ImGui::Text("Unity Matrices: %.0f", metrics_.matrixCount);
    ImGui::NextColumn();
    ImGui::Text("Eternal Tensors: %.0f", metrics_.tensorCount);
    ImGui::NextColumn();
    ImGui::Text("Eternal Clarities: %.0f", metrics_.clarityCount);
    ImGui::Columns(1);
}

void EternalConvergencePanel::RenderPerformanceMetrics() {
    ImGui::Text("Performance Metrics");
    ImGui::Separator();
    
    ImGui::Text("Tick Count: %llu", metrics_.tickCount);
    ImGui::Text("Current TPS: %.2f", metrics_.currentTPS);
    ImGui::Text("Current FPS: %.2f", metrics_.currentFPS);
    ImGui::Text("Tick Time: %.2f ms", metrics_.tickTimeMs);
    ImGui::Text("Frame Time: %.2f ms", metrics_.frameTimeMs);
    ImGui::Text("Target TPS: %d", metrics_.targetTPS);
    ImGui::Text("Target FPS: %d", metrics_.targetFPS);
    ImGui::Checkbox("Frame Limiting", &const_cast<bool&>(metrics_.frameLimitingEnabled));
    ImGui::Checkbox("Multi-Layer Sync", &const_cast<bool&>(metrics_.multiLayerSyncEnabled));
    ImGui::Checkbox("Cross-Layer Harmony", &const_cast<bool&>(metrics_.crossLayerHarmonyEnabled));
}

void EternalConvergencePanel::RenderResonanceMetrics() {
    ImGui::Text("Resonance Metrics");
    ImGui::Separator();
    
    ImGui::ProgressBar(static_cast<float>(metrics_.averageConvergence), ImVec2(0.0f, 0.0f), "Convergence");
    ImGui::ProgressBar(static_cast<float>(metrics_.averageUnity), ImVec2(0.0f, 0.0f), "Unity");
    ImGui::ProgressBar(static_cast<float>(metrics_.averageHarmony), ImVec2(0.0f, 0.0f), "Harmony");
    ImGui::ProgressBar(static_cast<float>(metrics_.averageCoherence), ImVec2(0.0f, 0.0f), "Coherence");
    ImGui::ProgressBar(static_cast<float>(metrics_.averageClarity), ImVec2(0.0f, 0.0f), "Clarity");
    ImGui::ProgressBar(static_cast<float>(metrics_.averageOmnipresence), ImVec2(0.0f, 0.0f), "Omnipresence");
    ImGui::ProgressBar(static_cast<float>(metrics_.averageContinuity), ImVec2(0.0f, 0.0f), "Continuity");
    
    ImGui::Separator();
    ImGui::Text("Resonance Levels:");
    ImGui::ProgressBar(static_cast<float>(metrics_.eternalResonance), ImVec2(0.0f, 0.0f), "Eternal");
    ImGui::ProgressBar(static_cast<float>(metrics_.unityResonance), ImVec2(0.0f, 0.0f), "Unity");
    ImGui::ProgressBar(static_cast<float>(metrics_.convergenceResonance), ImVec2(0.0f, 0.0f), "Convergence");
    ImGui::ProgressBar(static_cast<float>(metrics_.continuityResonance), ImVec2(0.0f, 0.0f), "Continuity");
    ImGui::ProgressBar(static_cast<float>(metrics_.omnipresenceResonance), ImVec2(0.0f, 0.0f), "Omnipresence");
    ImGui::ProgressBar(static_cast<float>(metrics_.coherenceResonance), ImVec2(0.0f, 0.0f), "Coherence");
    ImGui::ProgressBar(static_cast<float>(metrics_.clarityResonance), ImVec2(0.0f, 0.0f), "Clarity");
    ImGui::ProgressBar(static_cast<float>(metrics_.harmonyResonanceLevel), ImVec2(0.0f, 0.0f), "Harmony");
    ImGui::ProgressBar(static_cast<float>(metrics_.stabilityResonance), ImVec2(0.0f, 0.0f), "Stability");
    ImGui::ProgressBar(static_cast<float>(metrics_.densityResonance), ImVec2(0.0f, 0.0f), "Density");
    ImGui::ProgressBar(static_cast<float>(metrics_.purityResonance), ImVec2(0.0f, 0.0f), "Purity");
    ImGui::ProgressBar(static_cast<float>(metrics_.eternityResonance), ImVec2(0.0f, 0.0f), "Eternity");
}

void EternalConvergencePanel::RenderSyncStatus() {
    ImGui::Text("Synchronization Status");
    ImGui::Separator();
    
    ImGui::Text("Active Sync Threads: %d", metrics_.activeSyncThreads);
    ImGui::Text("Active Harmony Threads: %d", metrics_.activeHarmonyThreads);
    ImGui::ProgressBar(static_cast<float>(metrics_.syncEfficiency), ImVec2(0.0f, 0.0f), "Sync Efficiency");
    ImGui::ProgressBar(static_cast<float>(metrics_.harmonyResonance), ImVec2(0.0f, 0.0f), "Harmony Resonance");
    ImGui::ProgressBar(static_cast<float>(metrics_.crossLayerConvergence), ImVec2(0.0f, 0.0f), "Cross-Layer Convergence");
    
    if (ImGui::Button("Request Sync Pulse")) {
        RequestSyncPulse();
    }
    ImGui::SameLine();
    if (ImGui::Button("Request Harmony Pulse")) {
        RequestHarmonyPulse();
    }
}

void EternalConvergencePanel::RenderCreateEternalConvergenceDialog() {
    if (ImGui::BeginPopupModal("Create Eternal Convergence", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newEternalName, sizeof(state_.newEternalName));
        
        if (ImGui::Button("Create")) {
            if (strlen(state_.newEternalName) > 0) {
                EternalConvergence::EternalConvergenceEngine::GetInstance().CreateEternalConvergence(state_.newEternalName);
                RefreshData();
                memset(state_.newEternalName, 0, sizeof(state_.newEternalName));
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void EternalConvergencePanel::RenderCreateConvergenceNodeDialog() {
    if (ImGui::BeginPopupModal("Create Convergence Node", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newNodeName, sizeof(state_.newNodeName));
        
        static char eternalId[256] = "";
        ImGui::InputText("Eternal ID", eternalId, sizeof(eternalId));
        
        if (ImGui::Button("Create")) {
            if (strlen(state_.newNodeName) > 0 && strlen(eternalId) > 0) {
                EternalConvergence::EternalConvergenceEngine::GetInstance().CreateConvergenceNode(eternalId, state_.newNodeName);
                RefreshData();
                memset(state_.newNodeName, 0, sizeof(state_.newNodeName));
                memset(eternalId, 0, sizeof(eternalId));
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void EternalConvergencePanel::RenderCreateEternalStreamDialog() {
    if (ImGui::BeginPopupModal("Create Eternal Stream", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newStreamName, sizeof(state_.newStreamName));
        
        if (ImGui::Button("Create")) {
            if (strlen(state_.newStreamName) > 0) {
                EternalConvergence::EternalConvergenceEngine::GetInstance().CreateEternalStream(state_.newStreamName);
                RefreshData();
                memset(state_.newStreamName, 0, sizeof(state_.newStreamName));
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void EternalConvergencePanel::RenderCreateConvergenceWaveDialog() {
    if (ImGui::BeginPopupModal("Create Convergence Wave", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newWaveName, sizeof(state_.newWaveName));
        
        if (ImGui::Button("Create")) {
            if (strlen(state_.newWaveName) > 0) {
                EternalConvergence::EternalConvergenceEngine::GetInstance().CreateConvergenceWave(state_.newWaveName);
                RefreshData();
                memset(state_.newWaveName, 0, sizeof(state_.newWaveName));
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void EternalConvergencePanel::RenderCreateUnityMatrixDialog() {
    if (ImGui::BeginPopupModal("Create Unity Matrix", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newMatrixName, sizeof(state_.newMatrixName));
        
        if (ImGui::Button("Create")) {
            if (strlen(state_.newMatrixName) > 0) {
                EternalConvergence::EternalConvergenceEngine::GetInstance().CreateUnityMatrix(state_.newMatrixName);
                RefreshData();
                memset(state_.newMatrixName, 0, sizeof(state_.newMatrixName));
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void EternalConvergencePanel::RenderCreateEternalTensorDialog() {
    if (ImGui::BeginPopupModal("Create Eternal Tensor", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newTensorName, sizeof(state_.newTensorName));
        
        if (ImGui::Button("Create")) {
            if (strlen(state_.newTensorName) > 0) {
                EternalConvergence::EternalConvergenceEngine::GetInstance().CreateEternalTensor(state_.newTensorName);
                RefreshData();
                memset(state_.newTensorName, 0, sizeof(state_.newTensorName));
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void EternalConvergencePanel::RenderCreateEternalClarityDialog() {
    if (ImGui::BeginPopupModal("Create Eternal Clarity", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newClarityName, sizeof(state_.newClarityName));
        
        if (ImGui::Button("Create")) {
            if (strlen(state_.newClarityName) > 0) {
                EternalConvergence::EternalConvergenceEngine::GetInstance().CreateEternalClarity(state_.newClarityName);
                RefreshData();
                memset(state_.newClarityName, 0, sizeof(state_.newClarityName));
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void EternalConvergencePanel::RenderToolbar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Refresh", "F5")) {
                RefreshData();
            }
            if (ImGui::MenuItem("Clear Selection")) {
                ClearSelection();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Close", "Esc")) {
                isVisible_ = false;
            }
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Eternal Convergences", nullptr, &state_.showEternalConvergences);
            ImGui::MenuItem("Convergence Nodes", nullptr, &state_.showConvergenceNodes);
            ImGui::MenuItem("Eternal Streams", nullptr, &state_.showEternalStreams);
            ImGui::MenuItem("Convergence Waves", nullptr, &state_.showConvergenceWaves);
            ImGui::MenuItem("Unity Matrices", nullptr, &state_.showUnityMatrices);
            ImGui::MenuItem("Eternal Tensors", nullptr, &state_.showEternalTensors);
            ImGui::MenuItem("Eternal Clarities", nullptr, &state_.showEternalClarities);
            ImGui::MenuItem("Metrics", nullptr, &state_.showMetrics);
            ImGui::MenuItem("Visualization", nullptr, &state_.showVisualization);
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("Resonance")) {
            if (ImGui::MenuItem("Trigger Eternal")) TriggerEternalResonance();
            if (ImGui::MenuItem("Trigger Unity")) TriggerUnityResonance();
            if (ImGui::MenuItem("Trigger Convergence")) TriggerConvergenceResonance();
            if (ImGui::MenuItem("Trigger Continuity")) TriggerContinuityResonance();
            if (ImGui::MenuItem("Trigger Omnipresence")) TriggerOmnipresenceResonance();
            if (ImGui::MenuItem("Trigger Coherence")) TriggerCoherenceResonance();
            if (ImGui::MenuItem("Trigger Clarity")) TriggerClarityResonance();
            if (ImGui::MenuItem("Trigger Harmony")) TriggerHarmonyResonance();
            if (ImGui::MenuItem("Trigger Stability")) TriggerStabilityResonance();
            if (ImGui::MenuItem("Trigger Density")) TriggerDensityResonance();
            if (ImGui::MenuItem("Trigger Purity")) TriggerPurityResonance();
            if (ImGui::MenuItem("Trigger Eternity")) TriggerEternityResonance();
            ImGui::EndMenu();
        }
        
        ImGui::EndMenuBar();
    }
}

void EternalConvergencePanel::RenderStatusBar() {
    ImGui::Separator();
    ImGui::Text("Layer 121 - Eternal Convergence | Items: %zu | Running: %s | TPS: %.1f | FPS: %.1f",
        eternalConvergences_.size() + nodes_.size() + streams_.size() + waves_.size() + 
        matrices_.size() + tensors_.size() + clarities_.size(),
        metrics_.isRunning ? "Yes" : "No",
        metrics_.currentTPS,
        metrics_.currentFPS);
}

void EternalConvergencePanel::RenderSearchBar() {
    ImGui::InputText("Search", state_.searchFilter, sizeof(state_.searchFilter));
    ImGui::SameLine();
    ImGui::Checkbox("Auto Refresh", &state_.autoRefresh);
    ImGui::SameLine();
    ImGui::SliderFloat("Rate", &state_.refreshRate, 0.1f, 5.0f);
}

void EternalConvergencePanel::ApplyEternalTheme() {
    ImGui::StyleColorsDark();
}

void EternalConvergencePanel::RenderEternalBackground() {
    // Background rendering placeholder
}

} // namespace EternalConvergenceIDE
