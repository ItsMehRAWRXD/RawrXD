#include "AbsoluteUnityPanel.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>
#include <chrono>

namespace AbsoluteUnityIDE {

AbsoluteUnityPanel::AbsoluteUnityPanel() {}
AbsoluteUnityPanel::~AbsoluteUnityPanel() { Shutdown(); }

void AbsoluteUnityPanel::Initialize() {
    if (isInitialized_) return;
    memset(&state_, 0, sizeof(state_));
    state_.autoRefresh = true;
    state_.refreshRate = 1.0f;
    state_.matrixScale = 1.0f;
    state_.tensorScale = 1.0f;
    state_.showMatrixGrid = true;
    state_.showTensorGrid = true;
    RefreshData();
    isInitialized_ = true;
}

void AbsoluteUnityPanel::Shutdown() { isInitialized_ = false; }

void AbsoluteUnityPanel::Render() {
    if (!isVisible_ || !isInitialized_) return;
    auto currentTime = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000000.0f;
    if (state_.autoRefresh && (currentTime - state_.lastRefreshTime >= state_.refreshRate)) {
        RefreshData();
        state_.lastRefreshTime = currentTime;
    }
    ApplyAbsoluteTheme();
    ImGui::Begin("Absolute Unity (Layer 123)", &isVisible_, ImGuiWindowFlags_MenuBar);
    RenderToolbar();
    RenderSearchBar();
    if (ImGui::BeginTabBar("AbsoluteUnityTabs", ImGuiTabBarFlags_Reorderable)) {
        if (state_.showAbsoluteUnities && ImGui::BeginTabItem("Absolute Unities")) { RenderAbsoluteUnitiesTab(); ImGui::EndTabItem(); }
        if (state_.showUnityNodes && ImGui::BeginTabItem("Unity Nodes")) { RenderUnityNodesTab(); ImGui::EndTabItem(); }
        if (state_.showAbsoluteStreams && ImGui::BeginTabItem("Absolute Streams")) { RenderAbsoluteStreamsTab(); ImGui::EndTabItem(); }
        if (state_.showUnityWaves && ImGui::BeginTabItem("Unity Waves")) { RenderUnityWavesTab(); ImGui::EndTabItem(); }
        if (state_.showAbsoluteMatrices && ImGui::BeginTabItem("Absolute Matrices")) { RenderAbsoluteMatricesTab(); ImGui::EndTabItem(); }
        if (state_.showAbsoluteTensors && ImGui::BeginTabItem("Absolute Tensors")) { RenderAbsoluteTensorsTab(); ImGui::EndTabItem(); }
        if (state_.showAbsoluteClarities && ImGui::BeginTabItem("Absolute Clarities")) { RenderAbsoluteClaritiesTab(); ImGui::EndTabItem(); }
        if (state_.showMetrics && ImGui::BeginTabItem("Metrics")) { RenderMetricsTab(); ImGui::EndTabItem(); }
        if (state_.showVisualization && ImGui::BeginTabItem("Visualization")) { RenderVisualizationTab(); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    RenderStatusBar();
    ImGui::End();
}

void AbsoluteUnityPanel::RenderDockingLayout() {
    ImGuiID dockspace_id = ImGui::GetID("AbsoluteUnityDockspace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);
}

void AbsoluteUnityPanel::RefreshData() {
    std::lock_guard<std::mutex> lock(dataMutex_);
    auto& engine = AbsoluteUnity::AbsoluteUnityEngine::GetInstance();
    absoluteUnities_ = engine.GetAllAbsoluteUnities();
    nodes_ = engine.GetAllUnityNodes();
    streams_ = engine.GetAllAbsoluteStreams();
    waves_ = engine.GetAllUnityWaves();
    matrices_ = engine.GetAllAbsoluteMatrices();
    tensors_ = engine.GetAllAbsoluteTensors();
    clarities_ = engine.GetAllAbsoluteClarities();
    auto& loop = AbsoluteUnity::AbsoluteUnityLoop::GetInstance();
    metrics_ = loop.GetMetrics();
}

void AbsoluteUnityPanel::ClearSelection() {
    state_.selectedAbsoluteIndex = state_.selectedNodeIndex = state_.selectedStreamIndex = state_.selectedWaveIndex = 
    state_.selectedMatrixIndex = state_.selectedTensorIndex = state_.selectedClarityIndex = -1;
}

void AbsoluteUnityPanel::TriggerAbsoluteResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerAbsoluteResonance(); }
void AbsoluteUnityPanel::TriggerUnityResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerUnityResonance(); }
void AbsoluteUnityPanel::TriggerConvergenceResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerConvergenceResonance(); }
void AbsoluteUnityPanel::TriggerContinuityResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerContinuityResonance(); }
void AbsoluteUnityPanel::TriggerOmnipresenceResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerOmnipresenceResonance(); }
void AbsoluteUnityPanel::TriggerCoherenceResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerCoherenceResonance(); }
void AbsoluteUnityPanel::TriggerClarityResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerClarityResonance(); }
void AbsoluteUnityPanel::TriggerHarmonyResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerHarmonyResonance(); }
void AbsoluteUnityPanel::TriggerStabilityResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerStabilityResonance(); }
void AbsoluteUnityPanel::TriggerDensityResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerDensityResonance(); }
void AbsoluteUnityPanel::TriggerPurityResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerPurityResonance(); }
void AbsoluteUnityPanel::TriggerEternityResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerEternityResonance(); }
void AbsoluteUnityPanel::TriggerSupremacyResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerSupremacyResonance(); }
void AbsoluteUnityPanel::TriggerAbsolutenessResonance() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().TriggerAbsolutenessResonance(); }
void AbsoluteUnityPanel::RequestSyncPulse() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().RequestSyncPulse(); }
void AbsoluteUnityPanel::RequestHarmonyPulse() { AbsoluteUnity::AbsoluteUnityLoop::GetInstance().RequestHarmonyPulse(); }

void AbsoluteUnityPanel::RenderAbsoluteUnitiesTab() { ImGui::Columns(2); RenderAbsoluteUnityList(); ImGui::NextColumn(); RenderAbsoluteUnityDetails(); ImGui::Columns(1); }
void AbsoluteUnityPanel::RenderUnityNodesTab() { ImGui::Columns(2); RenderUnityNodeList(); ImGui::NextColumn(); RenderUnityNodeDetails(); ImGui::Columns(1); }
void AbsoluteUnityPanel::RenderAbsoluteStreamsTab() { ImGui::Columns(2); RenderAbsoluteStreamList(); ImGui::NextColumn(); RenderAbsoluteStreamDetails(); ImGui::Columns(1); }
void AbsoluteUnityPanel::RenderUnityWavesTab() { ImGui::Columns(2); RenderUnityWaveList(); ImGui::NextColumn(); RenderUnityWaveDetails(); ImGui::Columns(1); }
void AbsoluteUnityPanel::RenderAbsoluteMatricesTab() { ImGui::Columns(2); RenderAbsoluteMatrixList(); ImGui::NextColumn(); RenderAbsoluteMatrixDetails(); ImGui::Columns(1); }
void AbsoluteUnityPanel::RenderAbsoluteTensorsTab() { ImGui::Columns(2); RenderAbsoluteTensorList(); ImGui::NextColumn(); RenderAbsoluteTensorDetails(); ImGui::Columns(1); }
void AbsoluteUnityPanel::RenderAbsoluteClaritiesTab() { ImGui::Columns(2); RenderAbsoluteClarityList(); ImGui::NextColumn(); RenderAbsoluteClarityDetails(); ImGui::Columns(1); }
void AbsoluteUnityPanel::RenderMetricsTab() { RenderMetricsOverview(); ImGui::Separator(); RenderPerformanceMetrics(); ImGui::Separator(); RenderResonanceMetrics(); ImGui::Separator(); RenderSyncStatus(); }
void AbsoluteUnityPanel::RenderVisualizationTab() { RenderAbsoluteMatrixVisualization(); ImGui::Separator(); RenderAbsoluteTensorVisualization(); }

void AbsoluteUnityPanel::RenderAbsoluteUnityList() {
    ImGui::Text("Absolute Unities (%zu)", absoluteUnities_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Absolute Unity");
    RenderCreateAbsoluteUnityDialog();
    ImGui::BeginChild("AbsoluteUnityList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < absoluteUnities_.size(); i++) {
        const auto& u = absoluteUnities_[i];
        if (strlen(state_.searchFilter) > 0 && u->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(u->name.c_str(), state_.selectedAbsoluteIndex == (int)i)) state_.selectedAbsoluteIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void AbsoluteUnityPanel::RenderAbsoluteUnityDetails() {
    ImGui::Text("Absolute Unity Details"); ImGui::Separator();
    if (state_.selectedAbsoluteIndex >= 0 && state_.selectedAbsoluteIndex < (int)absoluteUnities_.size()) {
        const auto& u = absoluteUnities_[state_.selectedAbsoluteIndex];
        ImGui::Text("ID: %s", u->id.c_str()); ImGui::Text("Name: %s", u->name.c_str());
        ImGui::SliderFloat("Absoluteness", (float*)&u->absoluteness, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&u->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", (float*)&u->continuity, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&u->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&u->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence", (float*)&u->coherence, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", (float*)&u->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Eternity", (float*)&u->eternity, 0.0f, 1.0f);
        ImGui::SliderFloat("Supremacy", (float*)&u->supremacy, 0.0f, 1.0f);
        ImGui::Checkbox("Active", &u->isActive);
        if (ImGui::Button("Expand Absolute")) AbsoluteUnity::AbsoluteUnityEngine::GetInstance().ExpandAbsolute(u->id);
        ImGui::SameLine(); if (ImGui::Button("Amplify Unity")) AbsoluteUnity::AbsoluteUnityEngine::GetInstance().AmplifyUnity(u->id);
        ImGui::SameLine(); if (ImGui::Button("Achieve Absoluteness")) AbsoluteUnity::AbsoluteUnityEngine::GetInstance().AchieveAbsoluteness(u->id);
        ImGui::SameLine(); if (ImGui::Button("Delete")) { AbsoluteUnity::AbsoluteUnityEngine::GetInstance().DeleteAbsoluteUnity(u->id); RefreshData(); state_.selectedAbsoluteIndex = -1; }
    } else ImGui::Text("Select an absolute unity to view details");
}

void AbsoluteUnityPanel::RenderUnityNodeList() {
    ImGui::Text("Unity Nodes (%zu)", nodes_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Unity Node");
    RenderCreateUnityNodeDialog();
    ImGui::BeginChild("UnityNodeList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < nodes_.size(); i++) {
        const auto& n = nodes_[i];
        if (strlen(state_.searchFilter) > 0 && n->id.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(n->id.substr(0, 16).c_str(), state_.selectedNodeIndex == (int)i)) state_.selectedNodeIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void AbsoluteUnityPanel::RenderUnityNodeDetails() {
    ImGui::Text("Unity Node Details"); ImGui::Separator();
    if (state_.selectedNodeIndex >= 0 && state_.selectedNodeIndex < (int)nodes_.size()) {
        const auto& n = nodes_[state_.selectedNodeIndex];
        ImGui::Text("ID: %s", n->id.c_str()); ImGui::Text("Absolute ID: %s", n->absoluteId.c_str());
        ImGui::SliderFloat("Local Unity", (float*)&n->localUnity, 0.0f, 1.0f);
        ImGui::SliderFloat("Global Unity", (float*)&n->globalUnity, 0.0f, 1.0f);
        ImGui::SliderFloat("Resonance Factor", (float*)&n->resonanceFactor, 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence Level", (float*)&n->coherenceLevel, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity Index", (float*)&n->clarityIndex, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity Strength", (float*)&n->unityStrength, 0.0f, 1.0f);
        ImGui::SliderFloat("Absoluteness Level", (float*)&n->absolutenessLevel, 0.0f, 1.0f);
        ImGui::Checkbox("Unified", &n->isUnified); ImGui::Checkbox("Active", &n->isActive);
        if (ImGui::Button("Delete")) { AbsoluteUnity::AbsoluteUnityEngine::GetInstance().DeleteUnityNode(n->id); RefreshData(); state_.selectedNodeIndex = -1; }
    } else ImGui::Text("Select a unity node to view details");
}

void AbsoluteUnityPanel::RenderAbsoluteStreamList() {
    ImGui::Text("Absolute Streams (%zu)", streams_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Absolute Stream");
    RenderCreateAbsoluteStreamDialog();
    ImGui::BeginChild("AbsoluteStreamList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < streams_.size(); i++) {
        const auto& s = streams_[i];
        if (strlen(state_.searchFilter) > 0 && s->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(s->name.c_str(), state_.selectedStreamIndex == (int)i)) state_.selectedStreamIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void AbsoluteUnityPanel::RenderAbsoluteStreamDetails() {
    ImGui::Text("Absolute Stream Details"); ImGui::Separator();
    if (state_.selectedStreamIndex >= 0 && state_.selectedStreamIndex < (int)streams_.size()) {
        const auto& s = streams_[state_.selectedStreamIndex];
        ImGui::Text("ID: %s", s->id.c_str()); ImGui::Text("Name: %s", s->name.c_str());
        ImGui::SliderFloat("Stream Flow", (float*)&s->streamFlow, 0.0f, 1.0f);
        ImGui::SliderFloat("Density", (float*)&s->density, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", (float*)&s->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&s->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", (float*)&s->continuity, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&s->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&s->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Supremacy", (float*)&s->supremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Absoluteness", (float*)&s->absoluteness, 0.0f, 1.0f);
        ImGui::Checkbox("Active", &s->isActive);
        if (ImGui::Button("Delete")) { AbsoluteUnity::AbsoluteUnityEngine::GetInstance().DeleteAbsoluteStream(s->id); RefreshData(); state_.selectedStreamIndex = -1; }
    } else ImGui::Text("Select an absolute stream to view details");
}

void AbsoluteUnityPanel::RenderUnityWaveList() {
    ImGui::Text("Unity Waves (%zu)", waves_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Unity Wave");
    RenderCreateUnityWaveDialog();
    ImGui::BeginChild("UnityWaveList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < waves_.size(); i++) {
        const auto& w = waves_[i];
        if (strlen(state_.searchFilter) > 0 && w->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(w->name.c_str(), state_.selectedWaveIndex == (int)i)) state_.selectedWaveIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void AbsoluteUnityPanel::RenderUnityWaveDetails() {
    ImGui::Text("Unity Wave Details"); ImGui::Separator();
    if (state_.selectedWaveIndex >= 0 && state_.selectedWaveIndex < (int)waves_.size()) {
        const auto& w = waves_[state_.selectedWaveIndex];
        ImGui::Text("ID: %s", w->id.c_str()); ImGui::Text("Name: %s", w->name.c_str());
        ImGui::SliderFloat("Amplitude", (float*)&w->amplitude, 0.0f, 1.0f);
        ImGui::SliderFloat("Frequency", (float*)&w->frequency, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", (float*)&w->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&w->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&w->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", (float*)&w->continuity, 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence", (float*)&w->coherence, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&w->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Supremacy", (float*)&w->supremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Absoluteness", (float*)&w->absoluteness, 0.0f, 1.0f);
        ImGui::Checkbox("Active", &w->isActive);
        if (ImGui::Button("Delete")) { AbsoluteUnity::AbsoluteUnityEngine::GetInstance().DeleteUnityWave(w->id); RefreshData(); state_.selectedWaveIndex = -1; }
    } else ImGui::Text("Select a unity wave to view details");
}

void AbsoluteUnityPanel::RenderAbsoluteMatrixList() {
    ImGui::Text("Absolute Matrices (%zu)", matrices_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Absolute Matrix");
    RenderCreateAbsoluteMatrixDialog();
    ImGui::BeginChild("AbsoluteMatrixList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < matrices_.size(); i++) {
        const auto& m = matrices_[i];
        if (strlen(state_.searchFilter) > 0 && m->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(m->name.c_str(), state_.selectedMatrixIndex == (int)i)) state_.selectedMatrixIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void AbsoluteUnityPanel::RenderAbsoluteMatrixDetails() {
    ImGui::Text("Absolute Matrix Details"); ImGui::Separator();
    if (state_.selectedMatrixIndex >= 0 && state_.selectedMatrixIndex < (int)matrices_.size()) {
        const auto& m = matrices_[state_.selectedMatrixIndex];
        ImGui::Text("ID: %s", m->id.c_str()); ImGui::Text("Name: %s", m->name.c_str());
        ImGui::SliderFloat("Coherence", (float*)&m->coherence, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", (float*)&m->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&m->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", (float*)&m->continuity, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&m->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&m->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Supremacy", (float*)&m->supremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Absoluteness", (float*)&m->absoluteness, 0.0f, 1.0f);
        ImGui::SliderFloat("Stability", (float*)&m->stability, 0.0f, 1.0f);
        if (ImGui::Button("Unify Field")) { const_cast<AbsoluteUnity::AbsoluteMatrix*>(m.get())->UnifyField(); }
        ImGui::SameLine(); if (ImGui::Button("Delete")) { AbsoluteUnity::AbsoluteUnityEngine::GetInstance().DeleteAbsoluteMatrix(m->id); RefreshData(); state_.selectedMatrixIndex = -1; }
    } else ImGui::Text("Select an absolute matrix to view details");
}

void AbsoluteUnityPanel::RenderAbsoluteMatrixVisualization() {
    ImGui::Text("Absolute Matrix Visualization (13x13)"); ImGui::Separator();
    if (state_.selectedMatrixIndex >= 0 && state_.selectedMatrixIndex < (int)matrices_.size()) {
        const auto& m = matrices_[state_.selectedMatrixIndex];
        ImGui::SliderFloat("Scale", &state_.matrixScale, 0.5f, 2.0f); ImGui::Checkbox("Show Grid", &state_.showMatrixGrid);
        float cellSize = 16.0f * state_.matrixScale;
        ImVec2 startPos = ImGui::GetCursorScreenPos();
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        for (int i = 0; i < 13; i++) {
            for (int j = 0; j < 13; j++) {
                float value = (float)m->matrix[i][j];
                ImVec2 cellMin(startPos.x + j * cellSize, startPos.y + i * cellSize);
                ImVec2 cellMax(cellMin.x + cellSize - 1, cellMin.y + cellSize - 1);
                ImU32 color = ImGui::GetColorU32(ImVec4(value, value * 0.5f, value * 0.8f, 1.0f));
                drawList->AddRectFilled(cellMin, cellMax, color);
                if (state_.showMatrixGrid) drawList->AddRect(cellMin, cellMax, IM_COL32(100, 100, 100, 255));
                if (state_.selectedMatrixCell[0] == i && state_.selectedMatrixCell[1] == j) drawList->AddRect(cellMin, cellMax, IM_COL32(255, 255, 0, 255), 0.0f, 0, 2.0f);
            }
        }
        ImGui::Dummy(ImVec2(cellSize * 13, cellSize * 13));
        if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
            ImVec2 mousePos = ImGui::GetMousePos();
            ImVec2 relPos(mousePos.x - startPos.x, mousePos.y - startPos.y);
            int col = (int)(relPos.x / cellSize), row = (int)(relPos.y / cellSize);
            if (col >= 0 && col < 13 && row >= 0 && row < 13) { state_.selectedMatrixCell[0] = row; state_.selectedMatrixCell[1] = col; }
        }
        if (state_.selectedMatrixCell[0] >= 0) ImGui::Text("Selected Cell: [%d, %d] = %.3f", state_.selectedMatrixCell[0], state_.selectedMatrixCell[1], m->matrix[state_.selectedMatrixCell[0]][state_.selectedMatrixCell[1]]);
    } else ImGui::Text("Select an absolute matrix to visualize");
}

void AbsoluteUnityPanel::RenderAbsoluteTensorList() {
    ImGui::Text("Absolute Tensors (%zu)", tensors_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Absolute Tensor");
    RenderCreateAbsoluteTensorDialog();
    ImGui::BeginChild("AbsoluteTensorList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < tensors_.size(); i++) {
        const auto& t = tensors_[i];
        if (strlen(state_.searchFilter) > 0 && t->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(t->name.c_str(), state_.selectedTensorIndex == (int)i)) state_.selectedTensorIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void AbsoluteUnityPanel::RenderAbsoluteTensorDetails() {
    ImGui::Text("Absolute Tensor Details"); ImGui::Separator();
    if (state_.selectedTensorIndex >= 0 && state_.selectedTensorIndex < (int)tensors_.size()) {
        const auto& t = tensors_[state_.selectedTensorIndex];
        ImGui::Text("ID: %s", t->id.c_str()); ImGui::Text("Name: %s", t->name.c_str());
        ImGui::SliderFloat("Absoluteness", (float*)&t->absoluteness, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", (float*)&t->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&t->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&t->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&t->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Density", (float*)&t->density, 0.0f, 1.0f);
        ImGui::SliderFloat("Eternity", (float*)&t->eternity, 0.0f, 1.0f);
        ImGui::SliderFloat("Supremacy", (float*)&t->supremacy, 0.0f, 1.0f);
        if (ImGui::Button("Delete")) { AbsoluteUnity::AbsoluteUnityEngine::GetInstance().DeleteAbsoluteTensor(t->id); RefreshData(); state_.selectedTensorIndex = -1; }
    } else ImGui::Text("Select an absolute tensor to view details");
}

void AbsoluteUnityPanel::RenderAbsoluteTensorVisualization() {
    ImGui::Text("Absolute Tensor Visualization (10x10x10)"); ImGui::Separator();
    if (state_.selectedTensorIndex >= 0 && state_.selectedTensorIndex < (int)tensors_.size()) {
        const auto& t = tensors_[state_.selectedTensorIndex];
        ImGui::SliderFloat("Scale", &state_.tensorScale, 0.5f, 2.0f); ImGui::SliderInt("Slice", &state_.tensorViewMode, 0, 9); ImGui::Checkbox("Show Grid", &state_.showTensorGrid);
        float cellSize = 12.0f * state_.tensorScale; int slice = state_.tensorViewMode;
        ImVec2 startPos = ImGui::GetCursorScreenPos(); ImDrawList* drawList = ImGui::GetWindowDrawList();
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 10; j++) {
                float value = (float)t->tensor[slice][i][j];
                ImVec2 cellMin(startPos.x + j * cellSize, startPos.y + i * cellSize);
                ImVec2 cellMax(cellMin.x + cellSize - 1, cellMin.y + cellSize - 1);
                ImU32 color = ImGui::GetColorU32(ImVec4(value * 0.8f, value, value * 0.5f, 1.0f));
                drawList->AddRectFilled(cellMin, cellMax, color);
                if (state_.showTensorGrid) drawList->AddRect(cellMin, cellMax, IM_COL32(100, 100, 100, 255));
            }
        }
        ImGui::Dummy(ImVec2(cellSize * 10, cellSize * 10)); ImGui::Text("Slice %d of 10", slice + 1);
    } else ImGui::Text("Select an absolute tensor to visualize");
}

void AbsoluteUnityPanel::RenderAbsoluteClarityList() {
    ImGui::Text("Absolute Clarities (%zu)", clarities_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Absolute Clarity");
    RenderCreateAbsoluteClarityDialog();
    ImGui::BeginChild("AbsoluteClarityList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < clarities_.size(); i++) {
        const auto& c = clarities_[i];
        if (strlen(state_.searchFilter) > 0 && c->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(c->name.c_str(), state_.selectedClarityIndex == (int)i)) state_.selectedClarityIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void AbsoluteUnityPanel::RenderAbsoluteClarityDetails() {
    ImGui::Text("Absolute Clarity Details"); ImGui::Separator();
    if (state_.selectedClarityIndex >= 0 && state_.selectedClarityIndex < (int)clarities_.size()) {
        const auto& c = clarities_[state_.selectedClarityIndex];
        ImGui::Text("ID: %s", c->id.c_str()); ImGui::Text("Name: %s", c->name.c_str());
        ImGui::SliderFloat("Clarity", (float*)&c->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Purity", (float*)&c->purity, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&c->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", (float*)&c->continuity, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&c->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence", (float*)&c->coherence, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&c->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Density", (float*)&c->density, 0.0f, 1.0f);
        ImGui::SliderFloat("Supremacy", (float*)&c->supremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Absoluteness", (float*)&c->absoluteness, 0.0f, 1.0f);
        if (ImGui::Button("Delete")) { AbsoluteUnity::AbsoluteUnityEngine::GetInstance().DeleteAbsoluteClarity(c->id); RefreshData(); state_.selectedClarityIndex = -1; }
    } else ImGui::Text("Select an absolute clarity to view details");
}

void AbsoluteUnityPanel::RenderMetricsOverview() {
    ImGui::Text("Absolute Unity Metrics Overview"); ImGui::Separator();
    ImGui::Columns(4, "MetricsOverview");
    ImGui::Text("Absolute Unities: %.0f", metrics_.absoluteUnityCount); ImGui::NextColumn();
    ImGui::Text("Unity Nodes: %.0f", metrics_.nodeCount); ImGui::NextColumn();
    ImGui::Text("Absolute Streams: %.0f", metrics_.streamCount); ImGui::NextColumn();
    ImGui::Text("Unity Waves: %.0f", metrics_.waveCount); ImGui::NextColumn();
    ImGui::Text("Absolute Matrices: %.0f", metrics_.matrixCount); ImGui::NextColumn();
    ImGui::Text("Absolute Tensors: %.0f", metrics_.tensorCount); ImGui::NextColumn();
    ImGui::Text("Absolute Clarities: %.0f", metrics_.clarityCount); ImGui::Columns(1);
}

void AbsoluteUnityPanel::RenderPerformanceMetrics() {
    ImGui::Text("Performance Metrics"); ImGui::Separator();
    ImGui::Text("Tick Count: %llu", metrics_.tickCount);
    ImGui::Text("Current TPS: %.2f", metrics_.currentTPS); ImGui::Text("Current FPS: %.2f", metrics_.currentFPS);
    ImGui::Text("Tick Time: %.2f ms", metrics_.tickTimeMs); ImGui::Text("Frame Time: %.2f ms", metrics_.frameTimeMs);
    ImGui::Text("Target TPS: %d", metrics_.targetTPS); ImGui::Text("Target FPS: %d", metrics_.targetFPS);
    ImGui::Checkbox("Frame Limiting", (bool*)&metrics_.frameLimitingEnabled);
    ImGui::Checkbox("Multi-Layer Sync", (bool*)&metrics_.multiLayerSyncEnabled);
    ImGui::Checkbox("Cross-Layer Harmony", (bool*)&metrics_.crossLayerHarmonyEnabled);
}

void AbsoluteUnityPanel::RenderResonanceMetrics() {
    ImGui::Text("Resonance Metrics"); ImGui::Separator();
    ImGui::ProgressBar((float)metrics_.averageAbsoluteness, ImVec2(0.0f, 0.0f), "Absoluteness");
    ImGui::ProgressBar((float)metrics_.averageUnity, ImVec2(0.0f, 0.0f), "Unity");
    ImGui::ProgressBar((float)metrics_.averageHarmony, ImVec2(0.0f, 0.0f), "Harmony");
    ImGui::ProgressBar((float)metrics_.averageCoherence, ImVec2(0.0f, 0.0f), "Coherence");
    ImGui::ProgressBar((float)metrics_.averageClarity, ImVec2(0.0f, 0.0f), "Clarity");
    ImGui::ProgressBar((float)metrics_.averageEternity, ImVec2(0.0f, 0.0f), "Eternity");
    ImGui::ProgressBar((float)metrics_.averageSupremacy, ImVec2(0.0f, 0.0f), "Supremacy");
    ImGui::ProgressBar((float)metrics_.averageOmnipresence, ImVec2(0.0f, 0.0f), "Omnipresence");
    ImGui::ProgressBar((float)metrics_.averageContinuity, ImVec2(0.0f, 0.0f), "Continuity");
    ImGui::Separator(); ImGui::Text("Resonance Levels:");
    ImGui::ProgressBar((float)metrics_.absoluteResonance, ImVec2(0.0f, 0.0f), "Absolute");
    ImGui::ProgressBar((float)metrics_.unityResonance, ImVec2(0.0f, 0.0f), "Unity");
    ImGui::ProgressBar((float)metrics_.convergenceResonance, ImVec2(0.0f, 0.0f), "Convergence");
    ImGui::ProgressBar((float)metrics_.continuityResonance, ImVec2(0.0f, 0.0f), "Continuity");
    ImGui::ProgressBar((float)metrics_.omnipresenceResonance, ImVec2(0.0f, 0.0f), "Omnipresence");
    ImGui::ProgressBar((float)metrics_.coherenceResonance, ImVec2(0.0f, 0.0f), "Coherence");
    ImGui::ProgressBar((float)metrics_.clarityResonance, ImVec2(0.0f, 0.0f), "Clarity");
    ImGui::ProgressBar((float)metrics_.harmonyResonanceLevel, ImVec2(0.0f, 0.0f), "Harmony");
    ImGui::ProgressBar((float)metrics_.stabilityResonance, ImVec2(0.0f, 0.0f), "Stability");
    ImGui::ProgressBar((float)metrics_.densityResonance, ImVec2(0.0f, 0.0f), "Density");
    ImGui::ProgressBar((float)metrics_.purityResonance, ImVec2(0.0f, 0.0f), "Purity");
    ImGui::ProgressBar((float)metrics_.eternityResonance, ImVec2(0.0f, 0.0f), "Eternity");
    ImGui::ProgressBar((float)metrics_.supremacyResonance, ImVec2(0.0f, 0.0f), "Supremacy");
    ImGui::ProgressBar((float)metrics_.absolutenessResonance, ImVec2(0.0f, 0.0f), "Absoluteness");
}

void AbsoluteUnityPanel::RenderSyncStatus() {
    ImGui::Text("Synchronization Status"); ImGui::Separator();
    ImGui::Text("Active Sync Threads: %d", metrics_.activeSyncThreads);
    ImGui::Text("Active Harmony Threads: %d", metrics_.activeHarmonyThreads);
    ImGui::ProgressBar((float)metrics_.syncEfficiency, ImVec2(0.0f, 0.0f), "Sync Efficiency");
    ImGui::ProgressBar((float)metrics_.harmonyResonance, ImVec2(0.0f, 0.0f), "Harmony Resonance");
    ImGui::ProgressBar((float)metrics_.crossLayerConvergence, ImVec2(0.0f, 0.0f), "Cross-Layer Convergence");
    if (ImGui::Button("Request Sync Pulse")) RequestSyncPulse();
    ImGui::SameLine(); if (ImGui::Button("Request Harmony Pulse")) RequestHarmonyPulse();
}

void AbsoluteUnityPanel::RenderCreateAbsoluteUnityDialog() {
    if (ImGui::BeginPopupModal("Create Absolute Unity", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newAbsoluteName, sizeof(state_.newAbsoluteName));
        if (ImGui::Button("Create") && strlen(state_.newAbsoluteName) > 0) {
            AbsoluteUnity::AbsoluteUnityEngine::GetInstance().CreateAbsoluteUnity(state_.newAbsoluteName);
            RefreshData(); memset(state_.newAbsoluteName, 0, sizeof(state_.newAbsoluteName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void AbsoluteUnityPanel::RenderCreateUnityNodeDialog() {
    if (ImGui::BeginPopupModal("Create Unity Node", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newNodeName, sizeof(state_.newNodeName));
        static char absoluteId[256] = ""; ImGui::InputText("Absolute ID", absoluteId, sizeof(absoluteId));
        if (ImGui::Button("Create") && strlen(state_.newNodeName) > 0 && strlen(absoluteId) > 0) {
            AbsoluteUnity::AbsoluteUnityEngine::GetInstance().CreateUnityNode(absoluteId, state_.newNodeName);
            RefreshData(); memset(state_.newNodeName, 0, sizeof(state_.newNodeName)); memset(absoluteId, 0, sizeof(absoluteId)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void AbsoluteUnityPanel::RenderCreateAbsoluteStreamDialog() {
    if (ImGui::BeginPopupModal("Create Absolute Stream", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newStreamName, sizeof(state_.newStreamName));
        if (ImGui::Button("Create") && strlen(state_.newStreamName) > 0) {
            AbsoluteUnity::AbsoluteUnityEngine::GetInstance().CreateAbsoluteStream(state_.newStreamName);
            RefreshData(); memset(state_.newStreamName, 0, sizeof(state_.newStreamName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void AbsoluteUnityPanel::RenderCreateUnityWaveDialog() {
    if (ImGui::BeginPopupModal("Create Unity Wave", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newWaveName, sizeof(state_.newWaveName));
        if (ImGui::Button("Create") && strlen(state_.newWaveName) > 0) {
            AbsoluteUnity::AbsoluteUnityEngine::GetInstance().CreateUnityWave(state_.newWaveName);
            RefreshData(); memset(state_.newWaveName, 0, sizeof(state_.newWaveName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void AbsoluteUnityPanel::RenderCreateAbsoluteMatrixDialog() {
    if (ImGui::BeginPopupModal("Create Absolute Matrix", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newMatrixName, sizeof(state_.newMatrixName));
        if (ImGui::Button("Create") && strlen(state_.newMatrixName) > 0) {
            AbsoluteUnity::AbsoluteUnityEngine::GetInstance().CreateAbsoluteMatrix(state_.newMatrixName);
            RefreshData(); memset(state_.newMatrixName, 0, sizeof(state_.newMatrixName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void AbsoluteUnityPanel::RenderCreateAbsoluteTensorDialog() {
    if (ImGui::BeginPopupModal("Create Absolute Tensor", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newTensorName, sizeof(state_.newTensorName));
        if (ImGui::Button("Create") && strlen(state_.newTensorName) > 0) {
            AbsoluteUnity::AbsoluteUnityEngine::GetInstance().CreateAbsoluteTensor(state_.newTensorName);
            RefreshData(); memset(state_.newTensorName, 0, sizeof(state_.newTensorName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void AbsoluteUnityPanel::RenderCreateAbsoluteClarityDialog() {
    if (ImGui::BeginPopupModal("Create Absolute Clarity", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newClarityName, sizeof(state_.newClarityName));
        if (ImGui::Button("Create") && strlen(state_.newClarityName) > 0) {
            AbsoluteUnity::AbsoluteUnityEngine::GetInstance().CreateAbsoluteClarity(state_.newClarityName);
            RefreshData(); memset(state_.newClarityName, 0, sizeof(state_.newClarityName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void AbsoluteUnityPanel::RenderToolbar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Refresh", "F5")) RefreshData();
            if (ImGui::MenuItem("Clear Selection")) ClearSelection();
            ImGui::Separator();
            if (ImGui::MenuItem("Close", "Esc")) isVisible_ = false;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Absolute Unities", nullptr, &state_.showAbsoluteUnities);
            ImGui::MenuItem("Unity Nodes", nullptr, &state_.showUnityNodes);
            ImGui::MenuItem("Absolute Streams", nullptr, &state_.showAbsoluteStreams);
            ImGui::MenuItem("Unity Waves", nullptr, &state_.showUnityWaves);
            ImGui::MenuItem("Absolute Matrices", nullptr, &state_.showAbsoluteMatrices);
            ImGui::MenuItem("Absolute Tensors", nullptr, &state_.showAbsoluteTensors);
            ImGui::MenuItem("Absolute Clarities", nullptr, &state_.showAbsoluteClarities);
            ImGui::MenuItem("Metrics", nullptr, &state_.showMetrics);
            ImGui::MenuItem("Visualization", nullptr, &state_.showVisualization);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Resonance")) {
            if (ImGui::MenuItem("Trigger Absolute")) TriggerAbsoluteResonance();
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
            if (ImGui::MenuItem("Trigger Supremacy")) TriggerSupremacyResonance();
            if (ImGui::MenuItem("Trigger Absoluteness")) TriggerAbsolutenessResonance();
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}

void AbsoluteUnityPanel::RenderStatusBar() {
    ImGui::Separator();
    ImGui::Text("Layer 123 - Absolute Unity | Items: %zu | Running: %s | TPS: %.1f | FPS: %.1f",
        absoluteUnities_.size() + nodes_.size() + streams_.size() + waves_.size() + matrices_.size() + tensors_.size() + clarities_.size(),
        metrics_.isRunning ? "Yes" : "No", metrics_.currentTPS, metrics_.currentFPS);
}

void AbsoluteUnityPanel::RenderSearchBar() {
    ImGui::InputText("Search", state_.searchFilter, sizeof(state_.searchFilter));
    ImGui::SameLine(); ImGui::Checkbox("Auto Refresh", &state_.autoRefresh);
    ImGui::SameLine(); ImGui::SliderFloat("Rate", &state_.refreshRate, 0.1f, 5.0f);
}

void AbsoluteUnityPanel::ApplyAbsoluteTheme() { ImGui::StyleColorsDark(); }
void AbsoluteUnityPanel::RenderAbsoluteBackground() {}

} // namespace AbsoluteUnityIDE
