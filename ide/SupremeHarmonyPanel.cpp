#include "SupremeHarmonyPanel.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>
#include <chrono>

namespace SupremeHarmonyIDE {

SupremeHarmonyPanel::SupremeHarmonyPanel() {}
SupremeHarmonyPanel::~SupremeHarmonyPanel() { Shutdown(); }

void SupremeHarmonyPanel::Initialize() {
    if (isInitialized_) return;
    memset(state_.newSupremeName, 0, sizeof(state_.newSupremeName));
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

void SupremeHarmonyPanel::Shutdown() { isInitialized_ = false; }

void SupremeHarmonyPanel::Render() {
    if (!isVisible_ || !isInitialized_) return;
    auto currentTime = std::chrono::steady_clock::now().time_since_epoch().count() / 1000000000.0f;
    if (state_.autoRefresh && (currentTime - state_.lastRefreshTime >= state_.refreshRate)) {
        RefreshData();
        state_.lastRefreshTime = currentTime;
    }
    ApplySupremeTheme();
    ImGui::Begin("Supreme Harmony (Layer 122)", &isVisible_, ImGuiWindowFlags_MenuBar);
    RenderToolbar();
    RenderSearchBar();
    if (ImGui::BeginTabBar("SupremeHarmonyTabs", ImGuiTabBarFlags_Reorderable)) {
        if (state_.showSupremeHarmonies && ImGui::BeginTabItem("Supreme Harmonies")) { RenderSupremeHarmoniesTab(); ImGui::EndTabItem(); }
        if (state_.showHarmonyNodes && ImGui::BeginTabItem("Harmony Nodes")) { RenderHarmonyNodesTab(); ImGui::EndTabItem(); }
        if (state_.showSupremeStreams && ImGui::BeginTabItem("Supreme Streams")) { RenderSupremeStreamsTab(); ImGui::EndTabItem(); }
        if (state_.showHarmonyWaves && ImGui::BeginTabItem("Harmony Waves")) { RenderHarmonyWavesTab(); ImGui::EndTabItem(); }
        if (state_.showSupremeMatrices && ImGui::BeginTabItem("Supreme Matrices")) { RenderSupremeMatricesTab(); ImGui::EndTabItem(); }
        if (state_.showSupremeTensors && ImGui::BeginTabItem("Supreme Tensors")) { RenderSupremeTensorsTab(); ImGui::EndTabItem(); }
        if (state_.showSupremeClarities && ImGui::BeginTabItem("Supreme Clarities")) { RenderSupremeClaritiesTab(); ImGui::EndTabItem(); }
        if (state_.showMetrics && ImGui::BeginTabItem("Metrics")) { RenderMetricsTab(); ImGui::EndTabItem(); }
        if (state_.showVisualization && ImGui::BeginTabItem("Visualization")) { RenderVisualizationTab(); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    RenderStatusBar();
    ImGui::End();
}

void SupremeHarmonyPanel::RenderDockingLayout() {
    ImGuiID dockspace_id = ImGui::GetID("SupremeHarmonyDockspace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);
}

void SupremeHarmonyPanel::RefreshData() {
    std::lock_guard<std::mutex> lock(dataMutex_);
    auto& engine = SupremeHarmony::SupremeHarmonyEngine::GetInstance();
    supremeHarmonies_ = engine.GetAllSupremeHarmonies();
    nodes_ = engine.GetAllHarmonyNodes();
    streams_ = engine.GetAllSupremeStreams();
    waves_ = engine.GetAllHarmonyWaves();
    matrices_ = engine.GetAllSupremeMatrices();
    tensors_ = engine.GetAllSupremeTensors();
    clarities_ = engine.GetAllSupremeClarities();
    auto& loop = SupremeHarmony::SupremeHarmonyLoop::GetInstance();
    metrics_ = loop.GetMetrics();
}

void SupremeHarmonyPanel::ClearSelection() {
    state_.selectedSupremeIndex = state_.selectedNodeIndex = state_.selectedStreamIndex = state_.selectedWaveIndex = 
    state_.selectedMatrixIndex = state_.selectedTensorIndex = state_.selectedClarityIndex = -1;
}

void SupremeHarmonyPanel::TriggerSupremeResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerSupremeResonance(); }
void SupremeHarmonyPanel::TriggerUnityResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerUnityResonance(); }
void SupremeHarmonyPanel::TriggerConvergenceResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerConvergenceResonance(); }
void SupremeHarmonyPanel::TriggerContinuityResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerContinuityResonance(); }
void SupremeHarmonyPanel::TriggerOmnipresenceResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerOmnipresenceResonance(); }
void SupremeHarmonyPanel::TriggerCoherenceResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerCoherenceResonance(); }
void SupremeHarmonyPanel::TriggerClarityResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerClarityResonance(); }
void SupremeHarmonyPanel::TriggerHarmonyResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerHarmonyResonance(); }
void SupremeHarmonyPanel::TriggerStabilityResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerStabilityResonance(); }
void SupremeHarmonyPanel::TriggerDensityResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerDensityResonance(); }
void SupremeHarmonyPanel::TriggerPurityResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerPurityResonance(); }
void SupremeHarmonyPanel::TriggerEternityResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerEternityResonance(); }
void SupremeHarmonyPanel::TriggerSupremacyResonance() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().TriggerSupremacyResonance(); }
void SupremeHarmonyPanel::RequestSyncPulse() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().RequestSyncPulse(); }
void SupremeHarmonyPanel::RequestHarmonyPulse() { SupremeHarmony::SupremeHarmonyLoop::GetInstance().RequestHarmonyPulse(); }

void SupremeHarmonyPanel::RenderSupremeHarmoniesTab() { ImGui::Columns(2); RenderSupremeHarmonyList(); ImGui::NextColumn(); RenderSupremeHarmonyDetails(); ImGui::Columns(1); }
void SupremeHarmonyPanel::RenderHarmonyNodesTab() { ImGui::Columns(2); RenderHarmonyNodeList(); ImGui::NextColumn(); RenderHarmonyNodeDetails(); ImGui::Columns(1); }
void SupremeHarmonyPanel::RenderSupremeStreamsTab() { ImGui::Columns(2); RenderSupremeStreamList(); ImGui::NextColumn(); RenderSupremeStreamDetails(); ImGui::Columns(1); }
void SupremeHarmonyPanel::RenderHarmonyWavesTab() { ImGui::Columns(2); RenderHarmonyWaveList(); ImGui::NextColumn(); RenderHarmonyWaveDetails(); ImGui::Columns(1); }
void SupremeHarmonyPanel::RenderSupremeMatricesTab() { ImGui::Columns(2); RenderSupremeMatrixList(); ImGui::NextColumn(); RenderSupremeMatrixDetails(); ImGui::Columns(1); }
void SupremeHarmonyPanel::RenderSupremeTensorsTab() { ImGui::Columns(2); RenderSupremeTensorList(); ImGui::NextColumn(); RenderSupremeTensorDetails(); ImGui::Columns(1); }
void SupremeHarmonyPanel::RenderSupremeClaritiesTab() { ImGui::Columns(2); RenderSupremeClarityList(); ImGui::NextColumn(); RenderSupremeClarityDetails(); ImGui::Columns(1); }
void SupremeHarmonyPanel::RenderMetricsTab() { RenderMetricsOverview(); ImGui::Separator(); RenderPerformanceMetrics(); ImGui::Separator(); RenderResonanceMetrics(); ImGui::Separator(); RenderSyncStatus(); }
void SupremeHarmonyPanel::RenderVisualizationTab() { RenderSupremeMatrixVisualization(); ImGui::Separator(); RenderSupremeTensorVisualization(); }

void SupremeHarmonyPanel::RenderSupremeHarmonyList() {
    ImGui::Text("Supreme Harmonies (%zu)", supremeHarmonies_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Supreme Harmony");
    RenderCreateSupremeHarmonyDialog();
    ImGui::BeginChild("SupremeHarmonyList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < supremeHarmonies_.size(); i++) {
        const auto& h = supremeHarmonies_[i];
        if (strlen(state_.searchFilter) > 0 && h->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(h->name.c_str(), state_.selectedSupremeIndex == (int)i)) state_.selectedSupremeIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void SupremeHarmonyPanel::RenderSupremeHarmonyDetails() {
    ImGui::Text("Supreme Harmony Details"); ImGui::Separator();
    if (state_.selectedSupremeIndex >= 0 && state_.selectedSupremeIndex < (int)supremeHarmonies_.size()) {
        const auto& h = supremeHarmonies_[state_.selectedSupremeIndex];
        ImGui::Text("ID: %s", h->id.c_str()); ImGui::Text("Name: %s", h->name.c_str());
        ImGui::SliderFloat("Supremacy", (float*)&h->supremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&h->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Continuity", (float*)&h->continuity, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&h->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&h->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence", (float*)&h->coherence, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", (float*)&h->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Eternity", (float*)&h->eternity, 0.0f, 1.0f);
        ImGui::Checkbox("Active", &h->isActive);
        if (ImGui::Button("Expand Supreme")) SupremeHarmony::SupremeHarmonyEngine::GetInstance().ExpandSupreme(h->id);
        ImGui::SameLine(); if (ImGui::Button("Amplify Harmony")) SupremeHarmony::SupremeHarmonyEngine::GetInstance().AmplifyHarmony(h->id);
        ImGui::SameLine(); if (ImGui::Button("Elevate Supremacy")) SupremeHarmony::SupremeHarmonyEngine::GetInstance().ElevateSupremacy(h->id);
        ImGui::SameLine(); if (ImGui::Button("Delete")) { SupremeHarmony::SupremeHarmonyEngine::GetInstance().DeleteSupremeHarmony(h->id); RefreshData(); state_.selectedSupremeIndex = -1; }
    } else ImGui::Text("Select a supreme harmony to view details");
}

void SupremeHarmonyPanel::RenderHarmonyNodeList() {
    ImGui::Text("Harmony Nodes (%zu)", nodes_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Harmony Node");
    RenderCreateHarmonyNodeDialog();
    ImGui::BeginChild("HarmonyNodeList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < nodes_.size(); i++) {
        const auto& n = nodes_[i];
        if (strlen(state_.searchFilter) > 0 && n->id.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(n->id.substr(0, 16).c_str(), state_.selectedNodeIndex == (int)i)) state_.selectedNodeIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void SupremeHarmonyPanel::RenderHarmonyNodeDetails() {
    ImGui::Text("Harmony Node Details"); ImGui::Separator();
    if (state_.selectedNodeIndex >= 0 && state_.selectedNodeIndex < (int)nodes_.size()) {
        const auto& n = nodes_[state_.selectedNodeIndex];
        ImGui::Text("ID: %s", n->id.c_str()); ImGui::Text("Supreme ID: %s", n->supremeId.c_str());
        ImGui::SliderFloat("Local Harmony", (float*)&n->localHarmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Global Harmony", (float*)&n->globalHarmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Resonance Factor", (float*)&n->resonanceFactor, 0.0f, 1.0f);
        ImGui::SliderFloat("Coherence Level", (float*)&n->coherenceLevel, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity Index", (float*)&n->clarityIndex, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity Strength", (float*)&n->unityStrength, 0.0f, 1.0f);
        ImGui::SliderFloat("Supremacy Level", (float*)&n->supremacyLevel, 0.0f, 1.0f);
        ImGui::Checkbox("Unified", &n->isUnified); ImGui::Checkbox("Active", &n->isActive);
        if (ImGui::Button("Delete")) { SupremeHarmony::SupremeHarmonyEngine::GetInstance().DeleteHarmonyNode(n->id); RefreshData(); state_.selectedNodeIndex = -1; }
    } else ImGui::Text("Select a harmony node to view details");
}

void SupremeHarmonyPanel::RenderSupremeStreamList() {
    ImGui::Text("Supreme Streams (%zu)", streams_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Supreme Stream");
    RenderCreateSupremeStreamDialog();
    ImGui::BeginChild("SupremeStreamList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < streams_.size(); i++) {
        const auto& s = streams_[i];
        if (strlen(state_.searchFilter) > 0 && s->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(s->name.c_str(), state_.selectedStreamIndex == (int)i)) state_.selectedStreamIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void SupremeHarmonyPanel::RenderSupremeStreamDetails() {
    ImGui::Text("Supreme Stream Details"); ImGui::Separator();
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
        ImGui::Checkbox("Active", &s->isActive);
        if (ImGui::Button("Delete")) { SupremeHarmony::SupremeHarmonyEngine::GetInstance().DeleteSupremeStream(s->id); RefreshData(); state_.selectedStreamIndex = -1; }
    } else ImGui::Text("Select a supreme stream to view details");
}

void SupremeHarmonyPanel::RenderHarmonyWaveList() {
    ImGui::Text("Harmony Waves (%zu)", waves_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Harmony Wave");
    RenderCreateHarmonyWaveDialog();
    ImGui::BeginChild("HarmonyWaveList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < waves_.size(); i++) {
        const auto& w = waves_[i];
        if (strlen(state_.searchFilter) > 0 && w->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(w->name.c_str(), state_.selectedWaveIndex == (int)i)) state_.selectedWaveIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void SupremeHarmonyPanel::RenderHarmonyWaveDetails() {
    ImGui::Text("Harmony Wave Details"); ImGui::Separator();
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
        ImGui::Checkbox("Active", &w->isActive);
        if (ImGui::Button("Delete")) { SupremeHarmony::SupremeHarmonyEngine::GetInstance().DeleteHarmonyWave(w->id); RefreshData(); state_.selectedWaveIndex = -1; }
    } else ImGui::Text("Select a harmony wave to view details");
}

void SupremeHarmonyPanel::RenderSupremeMatrixList() {
    ImGui::Text("Supreme Matrices (%zu)", matrices_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Supreme Matrix");
    RenderCreateSupremeMatrixDialog();
    ImGui::BeginChild("SupremeMatrixList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < matrices_.size(); i++) {
        const auto& m = matrices_[i];
        if (strlen(state_.searchFilter) > 0 && m->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(m->name.c_str(), state_.selectedMatrixIndex == (int)i)) state_.selectedMatrixIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void SupremeHarmonyPanel::RenderSupremeMatrixDetails() {
    ImGui::Text("Supreme Matrix Details"); ImGui::Separator();
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
        ImGui::SliderFloat("Stability", (float*)&m->stability, 0.0f, 1.0f);
        if (ImGui::Button("Harmonize Field")) { const_cast<SupremeHarmony::SupremeMatrix*>(m.get())->HarmonizeField(); }
        ImGui::SameLine(); if (ImGui::Button("Delete")) { SupremeHarmony::SupremeHarmonyEngine::GetInstance().DeleteSupremeMatrix(m->id); RefreshData(); state_.selectedMatrixIndex = -1; }
    } else ImGui::Text("Select a supreme matrix to view details");
}

void SupremeHarmonyPanel::RenderSupremeMatrixVisualization() {
    ImGui::Text("Supreme Matrix Visualization (12x12)"); ImGui::Separator();
    if (state_.selectedMatrixIndex >= 0 && state_.selectedMatrixIndex < (int)matrices_.size()) {
        const auto& m = matrices_[state_.selectedMatrixIndex];
        ImGui::SliderFloat("Scale", &state_.matrixScale, 0.5f, 2.0f); ImGui::Checkbox("Show Grid", &state_.showMatrixGrid);
        float cellSize = 18.0f * state_.matrixScale;
        ImVec2 startPos = ImGui::GetCursorScreenPos();
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        for (int i = 0; i < 12; i++) {
            for (int j = 0; j < 12; j++) {
                float value = (float)m->matrix[i][j];
                ImVec2 cellMin(startPos.x + j * cellSize, startPos.y + i * cellSize);
                ImVec2 cellMax(cellMin.x + cellSize - 1, cellMin.y + cellSize - 1);
                ImU32 color = ImGui::GetColorU32(ImVec4(value, value * 0.5f, value * 0.8f, 1.0f));
                drawList->AddRectFilled(cellMin, cellMax, color);
                if (state_.showMatrixGrid) drawList->AddRect(cellMin, cellMax, IM_COL32(100, 100, 100, 255));
                if (state_.selectedMatrixCell[0] == i && state_.selectedMatrixCell[1] == j) drawList->AddRect(cellMin, cellMax, IM_COL32(255, 255, 0, 255), 0.0f, 0, 2.0f);
            }
        }
        ImGui::Dummy(ImVec2(cellSize * 12, cellSize * 12));
        if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
            ImVec2 mousePos = ImGui::GetMousePos();
            ImVec2 relPos(mousePos.x - startPos.x, mousePos.y - startPos.y);
            int col = (int)(relPos.x / cellSize), row = (int)(relPos.y / cellSize);
            if (col >= 0 && col < 12 && row >= 0 && row < 12) { state_.selectedMatrixCell[0] = row; state_.selectedMatrixCell[1] = col; }
        }
        if (state_.selectedMatrixCell[0] >= 0) ImGui::Text("Selected Cell: [%d, %d] = %.3f", state_.selectedMatrixCell[0], state_.selectedMatrixCell[1], m->matrix[state_.selectedMatrixCell[0]][state_.selectedMatrixCell[1]]);
    } else ImGui::Text("Select a supreme matrix to visualize");
}

void SupremeHarmonyPanel::RenderSupremeTensorList() {
    ImGui::Text("Supreme Tensors (%zu)", tensors_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Supreme Tensor");
    RenderCreateSupremeTensorDialog();
    ImGui::BeginChild("SupremeTensorList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < tensors_.size(); i++) {
        const auto& t = tensors_[i];
        if (strlen(state_.searchFilter) > 0 && t->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(t->name.c_str(), state_.selectedTensorIndex == (int)i)) state_.selectedTensorIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void SupremeHarmonyPanel::RenderSupremeTensorDetails() {
    ImGui::Text("Supreme Tensor Details"); ImGui::Separator();
    if (state_.selectedTensorIndex >= 0 && state_.selectedTensorIndex < (int)tensors_.size()) {
        const auto& t = tensors_[state_.selectedTensorIndex];
        ImGui::Text("ID: %s", t->id.c_str()); ImGui::Text("Name: %s", t->name.c_str());
        ImGui::SliderFloat("Supremacy", (float*)&t->supremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Clarity", (float*)&t->clarity, 0.0f, 1.0f);
        ImGui::SliderFloat("Harmony", (float*)&t->harmony, 0.0f, 1.0f);
        ImGui::SliderFloat("Omnipresence", (float*)&t->omnipresence, 0.0f, 1.0f);
        ImGui::SliderFloat("Unity", (float*)&t->unity, 0.0f, 1.0f);
        ImGui::SliderFloat("Density", (float*)&t->density, 0.0f, 1.0f);
        ImGui::SliderFloat("Eternity", (float*)&t->eternity, 0.0f, 1.0f);
        if (ImGui::Button("Delete")) { SupremeHarmony::SupremeHarmonyEngine::GetInstance().DeleteSupremeTensor(t->id); RefreshData(); state_.selectedTensorIndex = -1; }
    } else ImGui::Text("Select a supreme tensor to view details");
}

void SupremeHarmonyPanel::RenderSupremeTensorVisualization() {
    ImGui::Text("Supreme Tensor Visualization (9x9x9)"); ImGui::Separator();
    if (state_.selectedTensorIndex >= 0 && state_.selectedTensorIndex < (int)tensors_.size()) {
        const auto& t = tensors_[state_.selectedTensorIndex];
        ImGui::SliderFloat("Scale", &state_.tensorScale, 0.5f, 2.0f); ImGui::SliderInt("Slice", &state_.tensorViewMode, 0, 8); ImGui::Checkbox("Show Grid", &state_.showTensorGrid);
        float cellSize = 13.0f * state_.tensorScale; int slice = state_.tensorViewMode;
        ImVec2 startPos = ImGui::GetCursorScreenPos(); ImDrawList* drawList = ImGui::GetWindowDrawList();
        for (int i = 0; i < 9; i++) {
            for (int j = 0; j < 9; j++) {
                float value = (float)t->tensor[slice][i][j];
                ImVec2 cellMin(startPos.x + j * cellSize, startPos.y + i * cellSize);
                ImVec2 cellMax(cellMin.x + cellSize - 1, cellMin.y + cellSize - 1);
                ImU32 color = ImGui::GetColorU32(ImVec4(value * 0.8f, value, value * 0.5f, 1.0f));
                drawList->AddRectFilled(cellMin, cellMax, color);
                if (state_.showTensorGrid) drawList->AddRect(cellMin, cellMax, IM_COL32(100, 100, 100, 255));
            }
        }
        ImGui::Dummy(ImVec2(cellSize * 9, cellSize * 9)); ImGui::Text("Slice %d of 9", slice + 1);
    } else ImGui::Text("Select a supreme tensor to visualize");
}

void SupremeHarmonyPanel::RenderSupremeClarityList() {
    ImGui::Text("Supreme Clarities (%zu)", clarities_.size()); ImGui::Separator();
    if (ImGui::Button("Create New")) ImGui::OpenPopup("Create Supreme Clarity");
    RenderCreateSupremeClarityDialog();
    ImGui::BeginChild("SupremeClarityList", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
    for (size_t i = 0; i < clarities_.size(); i++) {
        const auto& c = clarities_[i];
        if (strlen(state_.searchFilter) > 0 && c->name.find(state_.searchFilter) == std::string::npos) continue;
        ImGui::PushID((int)i);
        if (ImGui::Selectable(c->name.c_str(), state_.selectedClarityIndex == (int)i)) state_.selectedClarityIndex = (int)i;
        ImGui::PopID();
    }
    ImGui::EndChild();
}

void SupremeHarmonyPanel::RenderSupremeClarityDetails() {
    ImGui::Text("Supreme Clarity Details"); ImGui::Separator();
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
        if (ImGui::Button("Delete")) { SupremeHarmony::SupremeHarmonyEngine::GetInstance().DeleteSupremeClarity(c->id); RefreshData(); state_.selectedClarityIndex = -1; }
    } else ImGui::Text("Select a supreme clarity to view details");
}

void SupremeHarmonyPanel::RenderMetricsOverview() {
    ImGui::Text("Supreme Harmony Metrics Overview"); ImGui::Separator();
    ImGui::Columns(4, "MetricsOverview");
    ImGui::Text("Supreme Harmonies: %.0f", metrics_.supremeHarmonyCount); ImGui::NextColumn();
    ImGui::Text("Harmony Nodes: %.0f", metrics_.nodeCount); ImGui::NextColumn();
    ImGui::Text("Supreme Streams: %.0f", metrics_.streamCount); ImGui::NextColumn();
    ImGui::Text("Harmony Waves: %.0f", metrics_.waveCount); ImGui::NextColumn();
    ImGui::Text("Supreme Matrices: %.0f", metrics_.matrixCount); ImGui::NextColumn();
    ImGui::Text("Supreme Tensors: %.0f", metrics_.tensorCount); ImGui::NextColumn();
    ImGui::Text("Supreme Clarities: %.0f", metrics_.clarityCount); ImGui::Columns(1);
}

void SupremeHarmonyPanel::RenderPerformanceMetrics() {
    ImGui::Text("Performance Metrics"); ImGui::Separator();
    ImGui::Text("Tick Count: %llu", metrics_.tickCount);
    ImGui::Text("Current TPS: %.2f", metrics_.currentTPS); ImGui::Text("Current FPS: %.2f", metrics_.currentFPS);
    ImGui::Text("Tick Time: %.2f ms", metrics_.tickTimeMs); ImGui::Text("Frame Time: %.2f ms", metrics_.frameTimeMs);
    ImGui::Text("Target TPS: %d", metrics_.targetTPS); ImGui::Text("Target FPS: %d", metrics_.targetFPS);
    ImGui::Checkbox("Frame Limiting", (bool*)&metrics_.frameLimitingEnabled);
    ImGui::Checkbox("Multi-Layer Sync", (bool*)&metrics_.multiLayerSyncEnabled);
    ImGui::Checkbox("Cross-Layer Harmony", (bool*)&metrics_.crossLayerHarmonyEnabled);
}

void SupremeHarmonyPanel::RenderResonanceMetrics() {
    ImGui::Text("Resonance Metrics"); ImGui::Separator();
    ImGui::ProgressBar((float)metrics_.averageSupremacy, ImVec2(0.0f, 0.0f), "Supremacy");
    ImGui::ProgressBar((float)metrics_.averageUnity, ImVec2(0.0f, 0.0f), "Unity");
    ImGui::ProgressBar((float)metrics_.averageHarmony, ImVec2(0.0f, 0.0f), "Harmony");
    ImGui::ProgressBar((float)metrics_.averageCoherence, ImVec2(0.0f, 0.0f), "Coherence");
    ImGui::ProgressBar((float)metrics_.averageClarity, ImVec2(0.0f, 0.0f), "Clarity");
    ImGui::ProgressBar((float)metrics_.averageEternity, ImVec2(0.0f, 0.0f), "Eternity");
    ImGui::ProgressBar((float)metrics_.averageOmnipresence, ImVec2(0.0f, 0.0f), "Omnipresence");
    ImGui::ProgressBar((float)metrics_.averageContinuity, ImVec2(0.0f, 0.0f), "Continuity");
    ImGui::Separator(); ImGui::Text("Resonance Levels:");
    ImGui::ProgressBar((float)metrics_.supremeResonance, ImVec2(0.0f, 0.0f), "Supreme");
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
}

void SupremeHarmonyPanel::RenderSyncStatus() {
    ImGui::Text("Synchronization Status"); ImGui::Separator();
    ImGui::Text("Active Sync Threads: %d", metrics_.activeSyncThreads);
    ImGui::Text("Active Harmony Threads: %d", metrics_.activeHarmonyThreads);
    ImGui::ProgressBar((float)metrics_.syncEfficiency, ImVec2(0.0f, 0.0f), "Sync Efficiency");
    ImGui::ProgressBar((float)metrics_.harmonyResonance, ImVec2(0.0f, 0.0f), "Harmony Resonance");
    ImGui::ProgressBar((float)metrics_.crossLayerConvergence, ImVec2(0.0f, 0.0f), "Cross-Layer Convergence");
    if (ImGui::Button("Request Sync Pulse")) RequestSyncPulse();
    ImGui::SameLine(); if (ImGui::Button("Request Harmony Pulse")) RequestHarmonyPulse();
}

void SupremeHarmonyPanel::RenderCreateSupremeHarmonyDialog() {
    if (ImGui::BeginPopupModal("Create Supreme Harmony", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newSupremeName, sizeof(state_.newSupremeName));
        if (ImGui::Button("Create") && strlen(state_.newSupremeName) > 0) {
            SupremeHarmony::SupremeHarmonyEngine::GetInstance().CreateSupremeHarmony(state_.newSupremeName);
            RefreshData(); memset(state_.newSupremeName, 0, sizeof(state_.newSupremeName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void SupremeHarmonyPanel::RenderCreateHarmonyNodeDialog() {
    if (ImGui::BeginPopupModal("Create Harmony Node", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newNodeName, sizeof(state_.newNodeName));
        static char supremeId[256] = ""; ImGui::InputText("Supreme ID", supremeId, sizeof(supremeId));
        if (ImGui::Button("Create") && strlen(state_.newNodeName) > 0 && strlen(supremeId) > 0) {
            SupremeHarmony::SupremeHarmonyEngine::GetInstance().CreateHarmonyNode(supremeId, state_.newNodeName);
            RefreshData(); memset(state_.newNodeName, 0, sizeof(state_.newNodeName)); memset(supremeId, 0, sizeof(supremeId)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void SupremeHarmonyPanel::RenderCreateSupremeStreamDialog() {
    if (ImGui::BeginPopupModal("Create Supreme Stream", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newStreamName, sizeof(state_.newStreamName));
        if (ImGui::Button("Create") && strlen(state_.newStreamName) > 0) {
            SupremeHarmony::SupremeHarmonyEngine::GetInstance().CreateSupremeStream(state_.newStreamName);
            RefreshData(); memset(state_.newStreamName, 0, sizeof(state_.newStreamName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void SupremeHarmonyPanel::RenderCreateHarmonyWaveDialog() {
    if (ImGui::BeginPopupModal("Create Harmony Wave", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newWaveName, sizeof(state_.newWaveName));
        if (ImGui::Button("Create") && strlen(state_.newWaveName) > 0) {
            SupremeHarmony::SupremeHarmonyEngine::GetInstance().CreateHarmonyWave(state_.newWaveName);
            RefreshData(); memset(state_.newWaveName, 0, sizeof(state_.newWaveName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void SupremeHarmonyPanel::RenderCreateSupremeMatrixDialog() {
    if (ImGui::BeginPopupModal("Create Supreme Matrix", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newMatrixName, sizeof(state_.newMatrixName));
        if (ImGui::Button("Create") && strlen(state_.newMatrixName) > 0) {
            SupremeHarmony::SupremeHarmonyEngine::GetInstance().CreateSupremeMatrix(state_.newMatrixName);
            RefreshData(); memset(state_.newMatrixName, 0, sizeof(state_.newMatrixName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void SupremeHarmonyPanel::RenderCreateSupremeTensorDialog() {
    if (ImGui::BeginPopupModal("Create Supreme Tensor", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newTensorName, sizeof(state_.newTensorName));
        if (ImGui::Button("Create") && strlen(state_.newTensorName) > 0) {
            SupremeHarmony::SupremeHarmonyEngine::GetInstance().CreateSupremeTensor(state_.newTensorName);
            RefreshData(); memset(state_.newTensorName, 0, sizeof(state_.newTensorName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void SupremeHarmonyPanel::RenderCreateSupremeClarityDialog() {
    if (ImGui::BeginPopupModal("Create Supreme Clarity", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("Name", state_.newClarityName, sizeof(state_.newClarityName));
        if (ImGui::Button("Create") && strlen(state_.newClarityName) > 0) {
            SupremeHarmony::SupremeHarmonyEngine::GetInstance().CreateSupremeClarity(state_.newClarityName);
            RefreshData(); memset(state_.newClarityName, 0, sizeof(state_.newClarityName)); ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(); if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void SupremeHarmonyPanel::RenderToolbar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Refresh", "F5")) RefreshData();
            if (ImGui::MenuItem("Clear Selection")) ClearSelection();
            ImGui::Separator();
            if (ImGui::MenuItem("Close", "Esc")) isVisible_ = false;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Supreme Harmonies", nullptr, &state_.showSupremeHarmonies);
            ImGui::MenuItem("Harmony Nodes", nullptr, &state_.showHarmonyNodes);
            ImGui::MenuItem("Supreme Streams", nullptr, &state_.showSupremeStreams);
            ImGui::MenuItem("Harmony Waves", nullptr, &state_.showHarmonyWaves);
            ImGui::MenuItem("Supreme Matrices", nullptr, &state_.showSupremeMatrices);
            ImGui::MenuItem("Supreme Tensors", nullptr, &state_.showSupremeTensors);
            ImGui::MenuItem("Supreme Clarities", nullptr, &state_.showSupremeClarities);
            ImGui::MenuItem("Metrics", nullptr, &state_.showMetrics);
            ImGui::MenuItem("Visualization", nullptr, &state_.showVisualization);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Resonance")) {
            if (ImGui::MenuItem("Trigger Supreme")) TriggerSupremeResonance();
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
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}

void SupremeHarmonyPanel::RenderStatusBar() {
    ImGui::Separator();
    ImGui::Text("Layer 122 - Supreme Harmony | Items: %zu | Running: %s | TPS: %.1f | FPS: %.1f",
        supremeHarmonies_.size() + nodes_.size() + streams_.size() + waves_.size() + matrices_.size() + tensors_.size() + clarities_.size(),
        metrics_.isRunning ? "Yes" : "No", metrics_.currentTPS, metrics_.currentFPS);
}

void SupremeHarmonyPanel::RenderSearchBar() {
    ImGui::InputText("Search", state_.searchFilter, sizeof(state_.searchFilter));
    ImGui::SameLine(); ImGui::Checkbox("Auto Refresh", &state_.autoRefresh);
    ImGui::SameLine(); ImGui::SliderFloat("Rate", &state_.refreshRate, 0.1f, 5.0f);
}

void SupremeHarmonyPanel::ApplySupremeTheme() { ImGui::StyleColorsDark(); }
void SupremeHarmonyPanel::RenderSupremeBackground() {}

} // namespace SupremeHarmonyIDE
