#pragma once

#include "cosmic/CosmicUnityEngine.hpp"
#include <cstring>
#include <vector>
#include <memory>

namespace IDE {

class CosmicUnityPanel {
public:
    CosmicUnityPanel();
    ~CosmicUnityPanel();

    void Initialize();
    void Shutdown();
    void Render();

    void SetVisible(bool visible);
    bool IsVisible() const { return isVisible_; }
    void ToggleVisibility() { isVisible_ = !isVisible_; }

    void RefreshData();

private:
    void RenderCosmicUnityTab();
    void RenderUnityNodesTab();
    void RenderCosmicStreamsTab();
    void RenderUnityWavesTab();
    void RenderSynthesisMatrixTab();
    void RenderCoherenceTensorTab();
    void RenderCosmicClarityTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    void RenderCosmicUnityList();
    void RenderCosmicUnityEditor();
    void RenderUnityNodeList();
    void RenderUnityNodeEditor();
    void RenderCosmicStreamList();
    void RenderCosmicStreamEditor();
    void RenderUnityWaveList();
    void RenderUnityWaveEditor();
    void RenderSynthesisMatrixList();
    void RenderSynthesisMatrixEditor();
    void RenderSynthesisMatrixVisualization();
    void RenderCoherenceTensorList();
    void RenderCoherenceTensorEditor();
    void RenderCoherenceTensorVisualization();
    void RenderCosmicClarityList();
    void RenderCosmicClarityEditor();

    void RenderMatrixCell(float value, int row, int col);
    void RenderTensorPlane(const CosmicUnity::CoherenceTensor& tensor, int plane);

    void CreateNewCosmicUnity();
    void CreateNewUnityNode();
    void CreateNewCosmicStream();
    void CreateNewUnityWave();
    void CreateNewSynthesisMatrix();
    void CreateNewCoherenceTensor();
    void CreateNewCosmicClarity();

    void DeleteSelectedCosmicUnity();
    void DeleteSelectedUnityNode();
    void DeleteSelectedCosmicStream();
    void DeleteSelectedUnityWave();
    void DeleteSelectedSynthesisMatrix();
    void DeleteSelectedCoherenceTensor();
    void DeleteSelectedCosmicClarity();

    void ApplyCosmicUnityActions();
    void ApplyUnityNodeActions();
    void ApplySynthesisMatrixActions();

    bool isVisible_ = false;
    bool isInitialized_ = false;
    int currentTab_ = 0;

    std::string selectedCosmicUnityId_;
    std::string selectedUnityNodeId_;
    std::string selectedCosmicStreamId_;
    std::string selectedUnityWaveId_;
    std::string selectedSynthesisMatrixId_;
    std::string selectedCoherenceTensorId_;
    std::string selectedCosmicClarityId_;

    char nameBuffer_[256];
    float unityValue_ = 0.5f;
    float synthesisValue_ = 0.5f;
    float continuityValue_ = 0.5f;
    float omnipresenceValue_ = 0.5f;
    float harmonyValue_ = 0.5f;
    float coherenceValue_ = 0.5f;
    float clarityValue_ = 0.5f;
    float localUnityValue_ = 0.5f;
    float globalUnityValue_ = 0.5f;
    float harmonyFactorValue_ = 0.5f;
    float synthesisStrengthValue_ = 0.5f;
    float streamFlowValue_ = 0.5f;
    float densityValue_ = 0.5f;
    float amplitudeValue_ = 0.5f;
    float frequencyValue_ = 0.5f;
    float purityValue_ = 0.5f;
    bool isUnified_ = false;
    bool isActive_ = true;

    float displayTPS_ = 0.0f;
    float displayFPS_ = 0.0f;
    uint64_t displayTickCount_ = 0;
    uint64_t displayFrameCount_ = 0;
    uint64_t displaySyncCount_ = 0;
    uint64_t displayHarmonyCount_ = 0;

    float targetTPS_ = 60.0f;
    float maxFPS_ = 60.0f;
    bool enableFrameLimiting_ = true;
    bool enableMetrics_ = true;
    bool enableOmnipresentTickPropagation_ = true;
    bool enableMultiLayerSynchronization_ = true;
    bool enableCrossLayerHarmonyHarmonization_ = true;
    float syncIntervalMs_ = 100.0f;
    float harmonyIntervalMs_ = 100.0f;

    std::vector<std::shared_ptr<CosmicUnity::CosmicUnity>> cachedCosmicUnities_;
    std::vector<std::shared_ptr<CosmicUnity::UnityNode>> cachedUnityNodes_;
    std::vector<std::shared_ptr<CosmicUnity::CosmicStream>> cachedCosmicStreams_;
    std::vector<std::shared_ptr<CosmicUnity::UnityWave>> cachedUnityWaves_;
    std::vector<std::shared_ptr<CosmicUnity::SynthesisMatrix>> cachedSynthesisMatrices_;
    std::vector<std::shared_ptr<CosmicUnity::CoherenceTensor>> cachedCoherenceTensors_;
    std::vector<std::shared_ptr<CosmicUnity::CosmicClarity>> cachedCosmicClarities_;

    float refreshTimer_ = 0.0f;
    const float refreshInterval_ = 0.5f;
};

extern CosmicUnityPanel g_cosmicUnityPanel;

} // namespace IDE
