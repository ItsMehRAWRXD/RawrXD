#include "InfiniteSynthesisPanel.hpp"
#include "infinite/InfiniteSynthesisLoop.hpp"
#include <cstring>
#include <algorithm>
#include <chrono>

namespace IDE {

InfiniteSynthesisPanel g_infiniteSynthesisPanel;

InfiniteSynthesisPanel::InfiniteSynthesisPanel() {
    std::memset(nameBuffer_, 0, sizeof(nameBuffer_));
}

InfiniteSynthesisPanel::~InfiniteSynthesisPanel() {
    Shutdown();
}

void InfiniteSynthesisPanel::Initialize() {
    if (isInitialized_) return;

    InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance().Initialize();
    InfiniteSynthesis::g_infiniteSynthesisLoop.Init();

    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();

    auto infiniteId = engine.CreateInfiniteSynthesis("Primary Infinite Synthesis");
    auto infinite = engine.GetInfiniteSynthesis(infiniteId);
    if (infinite) {
        infinite->synthesis = 0.9;
        infinite->integration = 0.85;
        infinite->continuity = 0.9;
        infinite->omnipresence = 0.85;
        infinite->harmony = 0.8;
        infinite->coherence = 0.85;
        infinite->clarity = 0.9;
        engine.UpdateInfiniteSynthesis(infiniteId, *infinite);
    }

    engine.CreateSynthesisNode(infiniteId, "Synthesis Node Alpha");
    engine.CreateSynthesisNode(infiniteId, "Synthesis Node Beta");
    engine.CreateInfiniteStream("Infinite Stream 1");
    engine.CreateSynthesisWave("Synthesis Wave 1");
    engine.CreateIntegrationMatrix("Integration Matrix 1");
    engine.CreateConvergenceTensor("Convergence Tensor 1");
    engine.CreateInfiniteClarity("Infinite Clarity 1");

    InfiniteSynthesis::g_infiniteSynthesisLoop.Start();

    RefreshData();
    isInitialized_ = true;
    isVisible_ = true;
}

void InfiniteSynthesisPanel::Shutdown() {
    if (!isInitialized_) return;

    InfiniteSynthesis::g_infiniteSynthesisLoop.Stop();
    InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance().Shutdown();
    isInitialized_ = false;
}

void InfiniteSynthesisPanel::SetVisible(bool visible) {
    isVisible_ = visible;
}

void InfiniteSynthesisPanel::RefreshData() {
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();

    cachedInfiniteSyntheses_ = engine.GetAllInfiniteSyntheses();
    cachedInfiniteStreams_ = engine.GetAllInfiniteStreams();
    cachedSynthesisWaves_ = engine.GetAllSynthesisWaves();
    cachedIntegrationMatrices_ = engine.GetAllIntegrationMatrices();
    cachedConvergenceTensors_ = engine.GetAllConvergenceTensors();
    cachedInfiniteClarities_ = engine.GetAllInfiniteClarities();
    
    if (!selectedInfiniteSynthesisId_.empty()) {
        cachedSynthesisNodes_ = engine.GetSynthesisNodesForInfinite(selectedInfiniteSynthesisId_);
    } else {
        cachedSynthesisNodes_.clear();
    }

    auto metrics = InfiniteSynthesis::g_infiniteSynthesisLoop.GetMetrics();
    displayTPS_ = static_cast<float>(metrics.currentTPS.load());
    displayFPS_ = static_cast<float>(metrics.currentFPS.load());
    displayTickCount_ = metrics.tickCount.load();
    displayFrameCount_ = metrics.frameCount.load();
    displaySyncCount_ = metrics.syncCount.load();
    displayHarmonyCount_ = metrics.harmonyCount.load();
}

void InfiniteSynthesisPanel::Render() {
    if (!isVisible_ || !isInitialized_) return;

    refreshTimer_ += 0.016f;
    if (refreshTimer_ >= refreshInterval_) {
        RefreshData();
        refreshTimer_ = 0.0f;
    }
}

void InfiniteSynthesisPanel::RenderInfiniteSynthesisTab() {}
void InfiniteSynthesisPanel::RenderSynthesisNodesTab() {}
void InfiniteSynthesisPanel::RenderInfiniteStreamsTab() {}
void InfiniteSynthesisPanel::RenderSynthesisWavesTab() {}
void InfiniteSynthesisPanel::RenderIntegrationMatrixTab() {}
void InfiniteSynthesisPanel::RenderConvergenceTensorTab() {}
void InfiniteSynthesisPanel::RenderInfiniteClarityTab() {}
void InfiniteSynthesisPanel::RenderMetricsTab() {}
void InfiniteSynthesisPanel::RenderSettingsTab() {}

void InfiniteSynthesisPanel::RenderInfiniteSynthesisList() {}
void InfiniteSynthesisPanel::RenderInfiniteSynthesisEditor() {}
void InfiniteSynthesisPanel::RenderSynthesisNodeList() {}
void InfiniteSynthesisPanel::RenderSynthesisNodeEditor() {}
void InfiniteSynthesisPanel::RenderInfiniteStreamList() {}
void InfiniteSynthesisPanel::RenderInfiniteStreamEditor() {}
void InfiniteSynthesisPanel::RenderSynthesisWaveList() {}
void InfiniteSynthesisPanel::RenderSynthesisWaveEditor() {}
void InfiniteSynthesisPanel::RenderIntegrationMatrixList() {}
void InfiniteSynthesisPanel::RenderIntegrationMatrixEditor() {}
void InfiniteSynthesisPanel::RenderIntegrationMatrixVisualization() {}
void InfiniteSynthesisPanel::RenderConvergenceTensorList() {}
void InfiniteSynthesisPanel::RenderConvergenceTensorEditor() {}
void InfiniteSynthesisPanel::RenderConvergenceTensorVisualization() {}
void InfiniteSynthesisPanel::RenderInfiniteClarityList() {}
void InfiniteSynthesisPanel::RenderInfiniteClarityEditor() {}

void InfiniteSynthesisPanel::RenderMatrixCell(float value, int row, int col) {}
void InfiniteSynthesisPanel::RenderTensorPlane(const InfiniteSynthesis::ConvergenceTensor& tensor, int plane) {}

void InfiniteSynthesisPanel::CreateNewInfiniteSynthesis() {
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Infinite Synthesis";
    engine.CreateInfiniteSynthesis(name);
    RefreshData();
}

void InfiniteSynthesisPanel::CreateNewSynthesisNode() {
    if (selectedInfiniteSynthesisId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Synthesis Node";
    engine.CreateSynthesisNode(selectedInfiniteSynthesisId_, name);
    RefreshData();
}

void InfiniteSynthesisPanel::CreateNewInfiniteStream() {
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Infinite Stream";
    engine.CreateInfiniteStream(name);
    RefreshData();
}

void InfiniteSynthesisPanel::CreateNewSynthesisWave() {
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Synthesis Wave";
    engine.CreateSynthesisWave(name);
    RefreshData();
}

void InfiniteSynthesisPanel::CreateNewIntegrationMatrix() {
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Integration Matrix";
    engine.CreateIntegrationMatrix(name);
    RefreshData();
}

void InfiniteSynthesisPanel::CreateNewConvergenceTensor() {
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Convergence Tensor";
    engine.CreateConvergenceTensor(name);
    RefreshData();
}

void InfiniteSynthesisPanel::CreateNewInfiniteClarity() {
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Infinite Clarity";
    engine.CreateInfiniteClarity(name);
    RefreshData();
}

void InfiniteSynthesisPanel::DeleteSelectedInfiniteSynthesis() {
    if (selectedInfiniteSynthesisId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    engine.DeleteInfiniteSynthesis(selectedInfiniteSynthesisId_);
    selectedInfiniteSynthesisId_.clear();
    RefreshData();
}

void InfiniteSynthesisPanel::DeleteSelectedSynthesisNode() {
    if (selectedSynthesisNodeId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    engine.DeleteSynthesisNode(selectedSynthesisNodeId_);
    selectedSynthesisNodeId_.clear();
    RefreshData();
}

void InfiniteSynthesisPanel::DeleteSelectedInfiniteStream() {
    if (selectedInfiniteStreamId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    engine.DeleteInfiniteStream(selectedInfiniteStreamId_);
    selectedInfiniteStreamId_.clear();
    RefreshData();
}

void InfiniteSynthesisPanel::DeleteSelectedSynthesisWave() {
    if (selectedSynthesisWaveId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    engine.DeleteSynthesisWave(selectedSynthesisWaveId_);
    selectedSynthesisWaveId_.clear();
    RefreshData();
}

void InfiniteSynthesisPanel::DeleteSelectedIntegrationMatrix() {
    if (selectedIntegrationMatrixId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    engine.DeleteIntegrationMatrix(selectedIntegrationMatrixId_);
    selectedIntegrationMatrixId_.clear();
    RefreshData();
}

void InfiniteSynthesisPanel::DeleteSelectedConvergenceTensor() {
    if (selectedConvergenceTensorId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    engine.DeleteConvergenceTensor(selectedConvergenceTensorId_);
    selectedConvergenceTensorId_.clear();
    RefreshData();
}

void InfiniteSynthesisPanel::DeleteSelectedInfiniteClarity() {
    if (selectedInfiniteClarityId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    engine.DeleteInfiniteClarity(selectedInfiniteClarityId_);
    selectedInfiniteClarityId_.clear();
    RefreshData();
}

void InfiniteSynthesisPanel::ApplyInfiniteSynthesisActions() {}
void InfiniteSynthesisPanel::ApplySynthesisNodeActions() {}

void InfiniteSynthesisPanel::ApplyIntegrationMatrixActions() {
    if (selectedIntegrationMatrixId_.empty()) return;
    auto& engine = InfiniteSynthesis::InfiniteSynthesisEngine::GetInstance();
    auto matrix = engine.GetIntegrationMatrix(selectedIntegrationMatrixId_);
    if (!matrix) return;

    matrix->StabilizeField();
    engine.UpdateIntegrationMatrix(selectedIntegrationMatrixId_, *matrix);
    RefreshData();
}

} // namespace IDE
