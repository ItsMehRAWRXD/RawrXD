#include "CosmicUnityPanel.hpp"
#include "cosmic/CosmicUnityLoop.hpp"
#include <cstring>
#include <algorithm>
#include <chrono>

namespace IDE {

CosmicUnityPanel g_cosmicUnityPanel;

CosmicUnityPanel::CosmicUnityPanel() {
    std::memset(nameBuffer_, 0, sizeof(nameBuffer_));
}

CosmicUnityPanel::~CosmicUnityPanel() {
    Shutdown();
}

void CosmicUnityPanel::Initialize() {
    if (isInitialized_) return;

    CosmicUnity::CosmicUnityEngine::GetInstance().Initialize();
    CosmicUnity::g_cosmicUnityLoop.Init();

    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();

    auto cosmicId = engine.CreateCosmicUnity("Primary Cosmic Unity");
    auto cosmic = engine.GetCosmicUnity(cosmicId);
    if (cosmic) {
        cosmic->unity = 0.85;
        cosmic->synthesis = 0.8;
        cosmic->continuity = 0.9;
        cosmic->omnipresence = 0.85;
        cosmic->harmony = 0.8;
        cosmic->coherence = 0.85;
        cosmic->clarity = 0.9;
        engine.UpdateCosmicUnity(cosmicId, *cosmic);
    }

    engine.CreateUnityNode(cosmicId, "Unity Node Alpha");
    engine.CreateUnityNode(cosmicId, "Unity Node Beta");
    engine.CreateCosmicStream("Cosmic Stream 1");
    engine.CreateUnityWave("Unity Wave 1");
    engine.CreateSynthesisMatrix("Synthesis Matrix 1");
    engine.CreateCoherenceTensor("Coherence Tensor 1");
    engine.CreateCosmicClarity("Cosmic Clarity 1");

    CosmicUnity::g_cosmicUnityLoop.Start();

    RefreshData();
    isInitialized_ = true;
    isVisible_ = true;
}

void CosmicUnityPanel::Shutdown() {
    if (!isInitialized_) return;

    CosmicUnity::g_cosmicUnityLoop.Stop();
    CosmicUnity::CosmicUnityEngine::GetInstance().Shutdown();
    isInitialized_ = false;
}

void CosmicUnityPanel::SetVisible(bool visible) {
    isVisible_ = visible;
}

void CosmicUnityPanel::RefreshData() {
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();

    cachedCosmicUnities_ = engine.GetAllCosmicUnities();
    cachedCosmicStreams_ = engine.GetAllCosmicStreams();
    cachedUnityWaves_ = engine.GetAllUnityWaves();
    cachedSynthesisMatrices_ = engine.GetAllSynthesisMatrices();
    cachedCoherenceTensors_ = engine.GetAllCoherenceTensors();
    cachedCosmicClarities_ = engine.GetAllCosmicClarities();
    
    // Get nodes for selected cosmic unity
    if (!selectedCosmicUnityId_.empty()) {
        cachedUnityNodes_ = engine.GetUnityNodesForCosmic(selectedCosmicUnityId_);
    } else {
        cachedUnityNodes_.clear();
    }

    auto metrics = CosmicUnity::g_cosmicUnityLoop.GetMetrics();
    displayTPS_ = static_cast<float>(metrics.currentTPS.load());
    displayFPS_ = static_cast<float>(metrics.currentFPS.load());
    displayTickCount_ = metrics.tickCount.load();
    displayFrameCount_ = metrics.frameCount.load();
    displaySyncCount_ = metrics.syncCount.load();
    displayHarmonyCount_ = metrics.harmonyCount.load();
}

void CosmicUnityPanel::Render() {
    if (!isVisible_ || !isInitialized_) return;

    refreshTimer_ += 0.016f;
    if (refreshTimer_ >= refreshInterval_) {
        RefreshData();
        refreshTimer_ = 0.0f;
    }
}

void CosmicUnityPanel::RenderCosmicUnityTab() {}
void CosmicUnityPanel::RenderUnityNodesTab() {}
void CosmicUnityPanel::RenderCosmicStreamsTab() {}
void CosmicUnityPanel::RenderUnityWavesTab() {}
void CosmicUnityPanel::RenderSynthesisMatrixTab() {}
void CosmicUnityPanel::RenderCoherenceTensorTab() {}
void CosmicUnityPanel::RenderCosmicClarityTab() {}
void CosmicUnityPanel::RenderMetricsTab() {}
void CosmicUnityPanel::RenderSettingsTab() {}

void CosmicUnityPanel::RenderCosmicUnityList() {}
void CosmicUnityPanel::RenderCosmicUnityEditor() {}
void CosmicUnityPanel::RenderUnityNodeList() {}
void CosmicUnityPanel::RenderUnityNodeEditor() {}
void CosmicUnityPanel::RenderCosmicStreamList() {}
void CosmicUnityPanel::RenderCosmicStreamEditor() {}
void CosmicUnityPanel::RenderUnityWaveList() {}
void CosmicUnityPanel::RenderUnityWaveEditor() {}
void CosmicUnityPanel::RenderSynthesisMatrixList() {}
void CosmicUnityPanel::RenderSynthesisMatrixEditor() {}
void CosmicUnityPanel::RenderSynthesisMatrixVisualization() {}
void CosmicUnityPanel::RenderCoherenceTensorList() {}
void CosmicUnityPanel::RenderCoherenceTensorEditor() {}
void CosmicUnityPanel::RenderCoherenceTensorVisualization() {}
void CosmicUnityPanel::RenderCosmicClarityList() {}
void CosmicUnityPanel::RenderCosmicClarityEditor() {}

void CosmicUnityPanel::RenderMatrixCell(float value, int row, int col) {}
void CosmicUnityPanel::RenderTensorPlane(const CosmicUnity::CoherenceTensor& tensor, int plane) {}

void CosmicUnityPanel::CreateNewCosmicUnity() {
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Cosmic Unity";
    engine.CreateCosmicUnity(name);
    RefreshData();
}

void CosmicUnityPanel::CreateNewUnityNode() {
    if (selectedCosmicUnityId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Unity Node";
    engine.CreateUnityNode(selectedCosmicUnityId_, name);
    RefreshData();
}

void CosmicUnityPanel::CreateNewCosmicStream() {
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Cosmic Stream";
    engine.CreateCosmicStream(name);
    RefreshData();
}

void CosmicUnityPanel::CreateNewUnityWave() {
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Unity Wave";
    engine.CreateUnityWave(name);
    RefreshData();
}

void CosmicUnityPanel::CreateNewSynthesisMatrix() {
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Synthesis Matrix";
    engine.CreateSynthesisMatrix(name);
    RefreshData();
}

void CosmicUnityPanel::CreateNewCoherenceTensor() {
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Coherence Tensor";
    engine.CreateCoherenceTensor(name);
    RefreshData();
}

void CosmicUnityPanel::CreateNewCosmicClarity() {
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    std::string name = nameBuffer_[0] ? nameBuffer_ : "New Cosmic Clarity";
    engine.CreateCosmicClarity(name);
    RefreshData();
}

void CosmicUnityPanel::DeleteSelectedCosmicUnity() {
    if (selectedCosmicUnityId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    engine.DeleteCosmicUnity(selectedCosmicUnityId_);
    selectedCosmicUnityId_.clear();
    RefreshData();
}

void CosmicUnityPanel::DeleteSelectedUnityNode() {
    if (selectedUnityNodeId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    engine.DeleteUnityNode(selectedUnityNodeId_);
    selectedUnityNodeId_.clear();
    RefreshData();
}

void CosmicUnityPanel::DeleteSelectedCosmicStream() {
    if (selectedCosmicStreamId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    engine.DeleteCosmicStream(selectedCosmicStreamId_);
    selectedCosmicStreamId_.clear();
    RefreshData();
}

void CosmicUnityPanel::DeleteSelectedUnityWave() {
    if (selectedUnityWaveId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    engine.DeleteUnityWave(selectedUnityWaveId_);
    selectedUnityWaveId_.clear();
    RefreshData();
}

void CosmicUnityPanel::DeleteSelectedSynthesisMatrix() {
    if (selectedSynthesisMatrixId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    engine.DeleteSynthesisMatrix(selectedSynthesisMatrixId_);
    selectedSynthesisMatrixId_.clear();
    RefreshData();
}

void CosmicUnityPanel::DeleteSelectedCoherenceTensor() {
    if (selectedCoherenceTensorId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    engine.DeleteCoherenceTensor(selectedCoherenceTensorId_);
    selectedCoherenceTensorId_.clear();
    RefreshData();
}

void CosmicUnityPanel::DeleteSelectedCosmicClarity() {
    if (selectedCosmicClarityId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    engine.DeleteCosmicClarity(selectedCosmicClarityId_);
    selectedCosmicClarityId_.clear();
    RefreshData();
}

void CosmicUnityPanel::ApplyCosmicUnityActions() {}
void CosmicUnityPanel::ApplyUnityNodeActions() {}

void CosmicUnityPanel::ApplySynthesisMatrixActions() {
    if (selectedSynthesisMatrixId_.empty()) return;
    auto& engine = CosmicUnity::CosmicUnityEngine::GetInstance();
    auto matrix = engine.GetSynthesisMatrix(selectedSynthesisMatrixId_);
    if (!matrix) return;

    matrix->StabilizeField();
    engine.UpdateSynthesisMatrix(selectedSynthesisMatrixId_, *matrix);
    RefreshData();
}

} // namespace IDE
