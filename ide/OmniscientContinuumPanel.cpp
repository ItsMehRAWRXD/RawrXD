#include "OmniscientContinuumPanel.hpp"
#include "../omniscient/OmniscientContinuumEngine.hpp"
#include "../omniscient/OmniscientContinuumLoop.hpp"
#include <imgui.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace IDE {

OmniscientContinuumPanel::OmniscientContinuumPanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

OmniscientContinuumPanel::~OmniscientContinuumPanel() {
    Shutdown();
}

bool OmniscientContinuumPanel::Initialize() {
    if (m_initialized) return true;
    
    if (!OmniscientContinuum::OmniscientContinuumEngine::Initialize()) {
        return false;
    }
    
    OmniscientContinuum::OmniscientContinuumLoopConfig loopConfig;
    loopConfig.targetTPS = 60;
    loopConfig.maxFPS = 60;
    loopConfig.enableFrameLimiting = true;
    loopConfig.enableMetrics = true;
    loopConfig.enableOmnipresentTickPropagation = true;
    loopConfig.enableMultiLayerSynchronization = true;
    loopConfig.enableCrossLayerResonance = true;
    
    if (!OmniscientContinuum::OmniscientContinuumLoop::Init(loopConfig)) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

void OmniscientContinuumPanel::Shutdown() {
    if (!m_initialized) return;
    
    OmniscientContinuum::OmniscientContinuumLoop::Shutdown();
    OmniscientContinuum::OmniscientContinuumEngine::Shutdown();
    
    m_initialized = false;
}

bool OmniscientContinuumPanel::IsInitialized() const {
    return m_initialized;
}

void OmniscientContinuumPanel::Show() {
    m_visible = true;
}

void OmniscientContinuumPanel::Hide() {
    m_visible = false;
}

void OmniscientContinuumPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool OmniscientContinuumPanel::IsVisible() const {
    return m_visible;
}

void OmniscientContinuumPanel::Render() {
    if (!m_visible || !m_initialized) return;
    RenderWindow();
}

void OmniscientContinuumPanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(1000, 750), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Omniscient Continuum (Layer 117)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::OmniscientField:
                RenderOmniscientFieldTab();
                break;
            case Tab::ContinuumNodes:
                RenderContinuumNodesTab();
                break;
            case Tab::AwarenessStreams:
                RenderAwarenessStreamsTab();
                break;
            case Tab::PerceptionWaves:
                RenderPerceptionWavesTab();
                break;
            case Tab::ResonanceMatrix:
                RenderResonanceMatrixTab();
                break;
            case Tab::ContinuityTensor:
                RenderContinuityTensorTab();
                break;
            case Tab::OmniscientClarity:
                RenderOmniscientClarityTab();
                break;
            case Tab::Metrics:
                RenderMetricsTab();
                break;
            case Tab::Settings:
                RenderSettingsTab();
                break;
            default:
                break;
        }
    }
    ImGui::End();
}

void OmniscientContinuumPanel::RenderTabBar() {
    if (ImGui::BeginTabBar("OmniscientContinuumTabs")) {
        if (ImGui::BeginTabItem("Omniscient Field")) {
            m_currentTab = static_cast<int>(Tab::OmniscientField);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Continuum Nodes")) {
            m_currentTab = static_cast<int>(Tab::ContinuumNodes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Awareness Streams")) {
            m_currentTab = static_cast<int>(Tab::AwarenessStreams);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Perception Waves")) {
            m_currentTab = static_cast<int>(Tab::PerceptionWaves);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Resonance Matrix")) {
            m_currentTab = static_cast<int>(Tab::ResonanceMatrix);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Continuity Tensor")) {
            m_currentTab = static_cast<int>(Tab::ContinuityTensor);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Omniscient Clarity")) {
            m_currentTab = static_cast<int>(Tab::OmniscientClarity);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Metrics")) {
            m_currentTab = static_cast<int>(Tab::Metrics);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Settings")) {
            m_currentTab = static_cast<int>(Tab::Settings);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void OmniscientContinuumPanel::RenderOmniscientFieldTab() {
    ImGui::Text("Omniscient Fields");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name", m_newFieldName, sizeof(m_newFieldName));
    ImGui::SameLine();
    if (ImGui::Button("Create")) {
        CreateNewOmniscientField();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto fieldIds = OmniscientContinuum::OmniscientContinuumEngine::GetAllOmniscientFieldIds();
    
    ImGui::BeginChild("FieldList", ImVec2(300, 0), true);
    for (const auto& id : fieldIds) {
        auto field = OmniscientContinuum::OmniscientContinuumEngine::GetOmniscientField(id);
        if (field && FilterMatches(field->name)) {
            bool isSelected = (m_selectedFieldId == id);
            if (ImGui::Selectable(field->name.c_str(), isSelected)) {
                SelectOmniscientField(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("FieldDetails", ImVec2(0, 0), true);
    if (!m_selectedFieldId.empty()) {
        RenderOmniscientFieldDetails(m_selectedFieldId);
    } else {
        ImGui::Text("Select an omniscient field to view details");
    }
    ImGui::EndChild();
}

void OmniscientContinuumPanel::RenderContinuumNodesTab() {
    ImGui::Text("Continuum Nodes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Node", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Node")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Node", m_newNodeName, sizeof(m_newNodeName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Node")) {
        CreateNewContinuumNode();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto nodeIds = OmniscientContinuum::OmniscientContinuumEngine::GetAllContinuumNodeIds();
    
    ImGui::BeginChild("NodeList", ImVec2(300, 0), true);
    for (const auto& id : nodeIds) {
        auto node = OmniscientContinuum::OmniscientContinuumEngine::GetContinuumNode(id);
        if (node && FilterMatches(node->name)) {
            bool isSelected = (m_selectedNodeId == id);
            if (ImGui::Selectable(node->name.c_str(), isSelected)) {
                SelectContinuumNode(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("NodeDetails", ImVec2(0, 0), true);
    if (!m_selectedNodeId.empty()) {
        RenderContinuumNodeDetails(m_selectedNodeId);
    } else {
        ImGui::Text("Select a continuum node to view details");
    }
    ImGui::EndChild();
}

void OmniscientContinuumPanel::RenderAwarenessStreamsTab() {
    ImGui::Text("Awareness Streams");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Stream", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Stream")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Stream", m_newStreamName, sizeof(m_newStreamName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Stream")) {
        CreateNewAwarenessStream();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto streamIds = OmniscientContinuum::OmniscientContinuumEngine::GetAllAwarenessStreamIds();
    
    ImGui::BeginChild("StreamList", ImVec2(300, 0), true);
    for (const auto& id : streamIds) {
        auto stream = OmniscientContinuum::OmniscientContinuumEngine::GetAwarenessStream(id);
        if (stream && FilterMatches(stream->name)) {
            bool isSelected = (m_selectedStreamId == id);
            if (ImGui::Selectable(stream->name.c_str(), isSelected)) {
                SelectAwarenessStream(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("StreamDetails", ImVec2(0, 0), true);
    if (!m_selectedStreamId.empty()) {
        RenderAwarenessStreamDetails(m_selectedStreamId);
    } else {
        ImGui::Text("Select an awareness stream to view details");
    }
    ImGui::EndChild();
}

void OmniscientContinuumPanel::RenderPerceptionWavesTab() {
    ImGui::Text("Perception Waves");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Wave", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Wave")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Wave", m_newWaveName, sizeof(m_newWaveName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Wave")) {
        CreateNewPerceptionWave();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto waveIds = OmniscientContinuum::OmniscientContinuumEngine::GetAllPerceptionWaveIds();
    
    ImGui::BeginChild("WaveList", ImVec2(300, 0), true);
    for (const auto& id : waveIds) {
        auto wave = OmniscientContinuum::OmniscientContinuumEngine::GetPerceptionWave(id);
        if (wave && FilterMatches(wave->name)) {
            bool isSelected = (m_selectedWaveId == id);
            if (ImGui::Selectable(wave->name.c_str(), isSelected)) {
                SelectPerceptionWave(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("WaveDetails", ImVec2(0, 0), true);
    if (!m_selectedWaveId.empty()) {
        RenderPerceptionWaveDetails(m_selectedWaveId);
    } else {
        ImGui::Text("Select a perception wave to view details");
    }
    ImGui::EndChild();
}

void OmniscientContinuumPanel::RenderResonanceMatrixTab() {
    ImGui::Text("Resonance Matrices");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Matrix", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Matrix")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Matrix", m_newMatrixName, sizeof(m_newMatrixName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Matrix")) {
        CreateNewResonanceMatrix();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto matrixIds = OmniscientContinuum::OmniscientContinuumEngine::GetAllResonanceMatrixIds();
    
    ImGui::BeginChild("MatrixList", ImVec2(300, 0), true);
    for (const auto& id : matrixIds) {
        auto matrix = OmniscientContinuum::OmniscientContinuumEngine::GetResonanceMatrix(id);
        if (matrix && FilterMatches(matrix->name)) {
            bool isSelected = (m_selectedMatrixId == id);
            if (ImGui::Selectable(matrix->name.c_str(), isSelected)) {
                SelectResonanceMatrix(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("MatrixDetails", ImVec2(0, 0), true);
    if (!m_selectedMatrixId.empty()) {
        RenderResonanceMatrixDetails(m_selectedMatrixId);
    } else {
        ImGui::Text("Select a resonance matrix to view details");
    }
    ImGui::EndChild();
}

void OmniscientContinuumPanel::RenderContinuityTensorTab() {
    ImGui::Text("Continuity Tensors");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Tensor", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Tensor")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Tensor", m_newTensorName, sizeof(m_newTensorName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Tensor")) {
        CreateNewContinuityTensor();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto tensorIds = OmniscientContinuum::OmniscientContinuumEngine::GetAllContinuityTensorIds();
    
    ImGui::BeginChild("TensorList", ImVec2(300, 0), true);
    for (const auto& id : tensorIds) {
        auto tensor = OmniscientContinuum::OmniscientContinuumEngine::GetContinuityTensor(id);
        if (tensor && FilterMatches(tensor->name)) {
            bool isSelected = (m_selectedTensorId == id);
            if (ImGui::Selectable(tensor->name.c_str(), isSelected)) {
                SelectContinuityTensor(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("TensorDetails", ImVec2(0, 0), true);
    if (!m_selectedTensorId.empty()) {
        RenderContinuityTensorDetails(m_selectedTensorId);
    } else {
        ImGui::Text("Select a continuity tensor to view details");
    }
    ImGui::EndChild();
}

void OmniscientContinuumPanel::RenderOmniscientClarityTab() {
    ImGui::Text("Omniscient Clarity");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Clarity", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Clarity")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Clarity", m_newClarityName, sizeof(m_newClarityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Clarity")) {
        CreateNewOmniscientClarity();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto clarityIds = OmniscientContinuum::OmniscientContinuumEngine::GetAllOmniscientClarityIds();
    
    ImGui::BeginChild("ClarityList", ImVec2(300, 0), true);
    for (const auto& id : clarityIds) {
        auto clarity = OmniscientContinuum::OmniscientContinuumEngine::GetOmniscientClarity(id);
        if (clarity && FilterMatches(clarity->name)) {
            bool isSelected = (m_selectedClarityId == id);
            if (ImGui::Selectable(clarity->name.c_str(), isSelected)) {
                SelectOmniscientClarity(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("ClarityDetails", ImVec2(0, 0), true);
    if (!m_selectedClarityId.empty()) {
        RenderOmniscientClarityDetails(m_selectedClarityId);
    } else {
        ImGui::Text("Select an omniscient clarity to view details");
    }
    ImGui::EndChild();
}

void OmniscientContinuumPanel::RenderMetricsTab() {
    ImGui::Text("Omniscient Continuum Metrics");
    ImGui::Separator();
    
    auto metrics = OmniscientContinuum::OmniscientContinuumLoop::GetMetrics();
    
    ImGui::Text("Performance Metrics:");
    DrawMetric("Current TPS", metrics.currentTPS, "%.1f");
    DrawMetric("Current FPS", metrics.currentFPS, "%.1f");
    DrawMetric("Average Tick Time (ms)", metrics.averageTickTimeMs, "%.3f");
    DrawMetric("Average Frame Time (ms)", metrics.averageFrameTimeMs, "%.3f");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Counters:");
    ImGui::Text("Total Ticks: %lld", metrics.totalTicks);
    ImGui::Text("Total Frames: %lld", metrics.totalFrames);
    ImGui::Text("Synchronized Layers: %lld", metrics.synchronizedLayers);
    ImGui::Text("Resonance Harmonizations: %lld", metrics.resonanceHarmonizations);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Engine Statistics:");
    ImGui::Text("Omniscient Fields: %zu", OmniscientContinuum::OmniscientContinuumEngine::GetAllOmniscientFieldIds().size());
    ImGui::Text("Continuum Nodes: %zu", OmniscientContinuum::OmniscientContinuumEngine::GetAllContinuumNodeIds().size());
    ImGui::Text("Awareness Streams: %zu", OmniscientContinuum::OmniscientContinuumEngine::GetAllAwarenessStreamIds().size());
    ImGui::Text("Perception Waves: %zu", OmniscientContinuum::OmniscientContinuumEngine::GetAllPerceptionWaveIds().size());
    ImGui::Text("Resonance Matrices: %zu", OmniscientContinuum::OmniscientContinuumEngine::GetAllResonanceMatrixIds().size());
    ImGui::Text("Continuity Tensors: %zu", OmniscientContinuum::OmniscientContinuumEngine::GetAllContinuityTensorIds().size());
    ImGui::Text("Omniscient Clarities: %zu", OmniscientContinuum::OmniscientContinuumEngine::GetAllOmniscientClarityIds().size());
}

void OmniscientContinuumPanel::RenderSettingsTab() {
    ImGui::Text("Omniscient Continuum Settings");
    ImGui::Separator();
    
    auto config = OmniscientContinuum::OmniscientContinuumLoop::GetConfig();
    
    bool changed = false;
    
    changed |= ImGui::InputInt("Target TPS", &config.targetTPS);
    changed |= ImGui::InputInt("Max FPS", &config.maxFPS);
    changed |= ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    changed |= ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    changed |= ImGui::Checkbox("Enable Omnipresent Tick Propagation", &config.enableOmnipresentTickPropagation);
    changed |= ImGui::Checkbox("Enable Multi-Layer Synchronization", &config.enableMultiLayerSynchronization);
    changed |= ImGui::Checkbox("Enable Cross-Layer Resonance", &config.enableCrossLayerResonance);
    
    if (changed) {
        OmniscientContinuum::OmniscientContinuumLoop::SetConfig(config);
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Loop Control:");
    
    if (OmniscientContinuum::OmniscientContinuumLoop::IsRunning()) {
        if (ImGui::Button("Stop Loop")) {
            OmniscientContinuum::OmniscientContinuumLoop::Stop();
        }
        ImGui::SameLine();
        if (OmniscientContinuum::OmniscientContinuumLoop::IsPaused()) {
            if (ImGui::Button("Resume")) {
                OmniscientContinuum::OmniscientContinuumLoop::Resume();
            }
        } else {
            if (ImGui::Button("Pause")) {
                OmniscientContinuum::OmniscientContinuumLoop::Pause();
            }
        }
    } else {
        if (ImGui::Button("Start Loop")) {
            OmniscientContinuum::OmniscientContinuumLoop::Start();
        }
    }
}

void OmniscientContinuumPanel::RenderOmniscientFieldDetails(const std::string& fieldId) {
    auto field = OmniscientContinuum::OmniscientContinuumEngine::GetOmniscientField(fieldId);
    if (!field) return;
    
    ImGui::Text("Name: %s", field->name.c_str());
    ImGui::Text("ID: %s", field->id.c_str());
    ImGui::Text("Created: %s", field->createdAt.c_str());
    ImGui::Text("Modified: %s", field->modifiedAt.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Awareness", field->awareness);
    DrawMetric("Perception", field->perception);
    DrawMetric("Continuity", field->continuity);
    DrawMetric("Omnipresence", field->omnipresence);
    DrawMetric("Resonance", field->resonance);
    DrawMetric("Coherence", field->coherence);
    DrawMetric("Clarity", field->clarity);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Expand Continuum")) {
        OnExpandContinuum(fieldId);
    }
    if (ImGui::Button("Amplify Resonance")) {
        OnAmplifyResonance(fieldId);
    }
    if (ImGui::Button("Strengthen Continuity")) {
        OnStrengthenContinuity(fieldId);
    }
    if (ImGui::Button("Clarify Omniscience")) {
        OnClarifyOmniscience(fieldId);
    }
}

void OmniscientContinuumPanel::RenderContinuumNodeDetails(const std::string& nodeId) {
    auto node = OmniscientContinuum::OmniscientContinuumEngine::GetContinuumNode(nodeId);
    if (!node) return;
    
    ImGui::Text("Name: %s", node->name.c_str());
    ImGui::Text("ID: %s", node->id.c_str());
    ImGui::Text("Is Unified: %s", node->isUnified ? "Yes" : "No");
    if (node->isUnified) {
        ImGui::Text("Unified At: %s", node->unifiedAt.c_str());
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Local Awareness", node->localAwareness);
    DrawMetric("Global Awareness", node->globalAwareness);
    DrawMetric("Resonance Factor", node->resonanceFactor);
    DrawMetric("Coherence Level", node->coherenceLevel);
    DrawMetric("Clarity Index", node->clarityIndex);
    DrawMetric("Continuity Strength", node->continuityStrength);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Merge Awareness")) {
        OnMergeAwareness(nodeId);
    }
    if (ImGui::Button("Unify Nodes")) {
        OnUnifyNodes(nodeId);
    }
}

void OmniscientContinuumPanel::RenderAwarenessStreamDetails(const std::string& streamId) {
    auto stream = OmniscientContinuum::OmniscientContinuumEngine::GetAwarenessStream(streamId);
    if (!stream) return;
    
    ImGui::Text("Name: %s", stream->name.c_str());
    ImGui::Text("ID: %s", stream->id.c_str());
    ImGui::Text("Is Active: %s", stream->isActive ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Stream Flow", stream->streamFlow);
    DrawMetric("Density", stream->density);
    DrawMetric("Clarity", stream->clarity);
    DrawMetric("Resonance", stream->resonance);
    DrawMetric("Continuity", stream->continuity);
    DrawMetric("Omnipresence", stream->omnipresence);
}

void OmniscientContinuumPanel::RenderPerceptionWaveDetails(const std::string& waveId) {
    auto wave = OmniscientContinuum::OmniscientContinuumEngine::GetPerceptionWave(waveId);
    if (!wave) return;
    
    ImGui::Text("Name: %s", wave->name.c_str());
    ImGui::Text("ID: %s", wave->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Amplitude", wave->amplitude);
    DrawMetric("Frequency", wave->frequency);
    DrawMetric("Clarity", wave->clarity);
    DrawMetric("Resonance", wave->resonance);
    DrawMetric("Omnipresence", wave->omnipresence);
    DrawMetric("Continuity", wave->continuity);
    DrawMetric("Coherence", wave->coherence);
}

void OmniscientContinuumPanel::RenderResonanceMatrixDetails(const std::string& matrixId) {
    auto matrix = OmniscientContinuum::OmniscientContinuumEngine::GetResonanceMatrix(matrixId);
    if (!matrix) return;
    
    ImGui::Text("Name: %s", matrix->name.c_str());
    ImGui::Text("ID: %s", matrix->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Coherence", matrix->coherence);
    DrawMetric("Clarity", matrix->clarity);
    DrawMetric("Resonance", matrix->resonance);
    DrawMetric("Continuity", matrix->continuity);
    DrawMetric("Omnipresence", matrix->omnipresence);
    DrawMetric("Stability", matrix->stability);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Matrix Visualization (7x7):");
    DrawMatrixVisualization(*matrix);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Stabilize Field")) {
        OnStabilizeField(matrixId);
    }
}

void OmniscientContinuumPanel::RenderContinuityTensorDetails(const std::string& tensorId) {
    auto tensor = OmniscientContinuum::OmniscientContinuumEngine::GetContinuityTensor(tensorId);
    if (!tensor) return;
    
    ImGui::Text("Name: %s", tensor->name.c_str());
    ImGui::Text("ID: %s", tensor->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Continuity", tensor->continuity);
    DrawMetric("Clarity", tensor->clarity);
    DrawMetric("Resonance", tensor->resonance);
    DrawMetric("Omnipresence", tensor->omnipresence);
    DrawMetric("Coherence", tensor->coherence);
    DrawMetric("Density", tensor->density);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Tensor Visualization (4x4x4):");
    DrawTensorVisualization(*tensor);
}

void OmniscientContinuumPanel::RenderOmniscientClarityDetails(const std::string& clarityId) {
    auto clarity = OmniscientContinuum::OmniscientContinuumEngine::GetOmniscientClarity(clarityId);
    if (!clarity) return;
    
    ImGui::Text("Name: %s", clarity->name.c_str());
    ImGui::Text("ID: %s", clarity->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Clarity", clarity->clarity);
    DrawMetric("Purity", clarity->purity);
    DrawMetric("Resonance", clarity->resonance);
    DrawMetric("Continuity", clarity->continuity);
    DrawMetric("Omnipresence", clarity->omnipresence);
    DrawMetric("Coherence", clarity->coherence);
    DrawMetric("Density", clarity->density);
}

void OmniscientContinuumPanel::SelectOmniscientField(const std::string& fieldId) {
    m_selectedFieldId = fieldId;
}

void OmniscientContinuumPanel::SelectContinuumNode(const std::string& nodeId) {
    m_selectedNodeId = nodeId;
}

void OmniscientContinuumPanel::SelectAwarenessStream(const std::string& streamId) {
    m_selectedStreamId = streamId;
}

void OmniscientContinuumPanel::SelectPerceptionWave(const std::string& waveId) {
    m_selectedWaveId = waveId;
}

void OmniscientContinuumPanel::SelectResonanceMatrix(const std::string& matrixId) {
    m_selectedMatrixId = matrixId;
}

void OmniscientContinuumPanel::SelectContinuityTensor(const std::string& tensorId) {
    m_selectedTensorId = tensorId;
}

void OmniscientContinuumPanel::SelectOmniscientClarity(const std::string& clarityId) {
    m_selectedClarityId = clarityId;
}

void OmniscientContinuumPanel::CreateNewOmniscientField() {
    if (std::strlen(m_newFieldName) > 0) {
        OmniscientContinuum::OmniscientContinuumEngine::CreateOmniscientField(m_newFieldName);
        std::memset(m_newFieldName, 0, sizeof(m_newFieldName));
    }
}

void OmniscientContinuumPanel::CreateNewContinuumNode() {
    if (std::strlen(m_newNodeName) > 0) {
        OmniscientContinuum::OmniscientContinuumEngine::CreateContinuumNode(m_newNodeName);
        std::memset(m_newNodeName, 0, sizeof(m_newNodeName));
    }
}

void OmniscientContinuumPanel::CreateNewAwarenessStream() {
    if (std::strlen(m_newStreamName) > 0) {
        OmniscientContinuum::OmniscientContinuumEngine::CreateAwarenessStream(m_newStreamName);
        std::memset(m_newStreamName, 0, sizeof(m_newStreamName));
    }
}

void OmniscientContinuumPanel::CreateNewPerceptionWave() {
    if (std::strlen(m_newWaveName) > 0) {
        OmniscientContinuum::OmniscientContinuumEngine::CreatePerceptionWave(m_newWaveName);
        std::memset(m_newWaveName, 0, sizeof(m_newWaveName));
    }
}

void OmniscientContinuumPanel::CreateNewResonanceMatrix() {
    if (std::strlen(m_newMatrixName) > 0) {
        OmniscientContinuum::OmniscientContinuumEngine::CreateResonanceMatrix(m_newMatrixName);
        std::memset(m_newMatrixName, 0, sizeof(m_newMatrixName));
    }
}

void OmniscientContinuumPanel::CreateNewContinuityTensor() {
    if (std::strlen(m_newTensorName) > 0) {
        OmniscientContinuum::OmniscientContinuumEngine::CreateContinuityTensor(m_newTensorName);
        std::memset(m_newTensorName, 0, sizeof(m_newTensorName));
    }
}

void OmniscientContinuumPanel::CreateNewOmniscientClarity() {
    if (std::strlen(m_newClarityName) > 0) {
        OmniscientContinuum::OmniscientContinuumEngine::CreateOmniscientClarity(m_newClarityName);
        std::memset(m_newClarityName, 0, sizeof(m_newClarityName));
    }
}

void OmniscientContinuumPanel::ClearInputBuffers() {
    std::memset(m_newFieldName, 0, sizeof(m_newFieldName));
    std::memset(m_newNodeName, 0, sizeof(m_newNodeName));
    std::memset(m_newStreamName, 0, sizeof(m_newStreamName));
    std::memset(m_newWaveName, 0, sizeof(m_newWaveName));
    std::memset(m_newMatrixName, 0, sizeof(m_newMatrixName));
    std::memset(m_newTensorName, 0, sizeof(m_newTensorName));
    std::memset(m_newClarityName, 0, sizeof(m_newClarityName));
}

bool OmniscientContinuumPanel::FilterMatches(const std::string& text) const {
    if (std::strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

void OmniscientContinuumPanel::DrawProgressBar(float value, const ImVec4& color) {
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::ProgressBar(value, ImVec2(-1, 0), "");
    ImGui::PopStyleColor();
}

void OmniscientContinuumPanel::DrawMetric(const char* label, float value, const char* format) {
    ImGui::Text("%s: ", label);
    ImGui::SameLine();
    ImGui::Text(format, value);
}

void OmniscientContinuumPanel::DrawMatrixVisualization(const OmniscientContinuum::ResonanceMatrix& matrix) {
    ImGui::BeginChild("MatrixViz", ImVec2(300, 300), true);
    
    float cellSize = 35.0f;
    for (int i = 0; i < 7; i++) {
        for (int j = 0; j < 7; j++) {
            float val = matrix.matrix[i][j];
            ImVec4 color = ImVec4(val, val, val, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Button, color);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, color);
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, color);
            
            char label[8];
            snprintf(label, sizeof(label), "%.1f", val);
            ImGui::Button(label, ImVec2(cellSize, cellSize));
            
            ImGui::PopStyleColor(3);
            
            if (j < 6) ImGui::SameLine();
        }
    }
    
    ImGui::EndChild();
}

void OmniscientContinuumPanel::DrawTensorVisualization(const OmniscientContinuum::ContinuityTensor& tensor) {
    ImGui::Text("Tensor Planes (4 layers of 4x4):");
    
    for (int z = 0; z < 4; z++) {
        ImGui::Text("Plane %d:", z + 1);
        
        float cellSize = 30.0f;
        for (int y = 0; y < 4; y++) {
            for (int x = 0; x < 4; x++) {
                float val = tensor.tensor[z][y][x];
                ImVec4 color = ImVec4(val, val, val, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Button, color);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, color);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, color);
                
                char label[8];
                snprintf(label, sizeof(label), "%.1f", val);
                ImGui::Button(label, ImVec2(cellSize, cellSize));
                
                ImGui::PopStyleColor(3);
                
                if (x < 3) ImGui::SameLine();
            }
        }
        ImGui::Spacing();
    }
}

// Action handlers
void OmniscientContinuumPanel::OnExpandContinuum(const std::string& fieldId) {
    OmniscientContinuum::OmniscientContinuumEngine::ExpandContinuum(fieldId);
}

void OmniscientContinuumPanel::OnMergeAwareness(const std::string& nodeId) {
    OmniscientContinuum::OmniscientContinuumEngine::MergeAwareness(nodeId);
}

void OmniscientContinuumPanel::OnAmplifyResonance(const std::string& fieldId) {
    OmniscientContinuum::OmniscientContinuumEngine::AmplifyResonance(fieldId);
}

void OmniscientContinuumPanel::OnStrengthenContinuity(const std::string& fieldId) {
    OmniscientContinuum::OmniscientContinuumEngine::StrengthenContinuity(fieldId);
}

void OmniscientContinuumPanel::OnClarifyOmniscience(const std::string& fieldId) {
    OmniscientContinuum::OmniscientContinuumEngine::ClarifyOmniscience(fieldId);
}

void OmniscientContinuumPanel::OnStabilizeField(const std::string& matrixId) {
    OmniscientContinuum::OmniscientContinuumEngine::StabilizeField(matrixId);
}

void OmniscientContinuumPanel::OnUnifyNodes(const std::string& nodeId) {
    OmniscientContinuum::OmniscientContinuumEngine::UnifyNodes(nodeId);
}

} // namespace IDE
