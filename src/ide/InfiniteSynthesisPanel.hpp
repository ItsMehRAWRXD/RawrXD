#pragma once

#include "infinite/InfiniteSynthesisEngine.hpp"
#include <cstring>
#include <vector>
#include <memory>

namespace IDE {

class InfiniteSynthesisPanel {
public:
    InfiniteSynthesisPanel();
    ~InfiniteSynthesisPanel();

    void Initialize();
    void Shutdown();
    void Render();

    void SetVisible(bool visible);
    bool IsVisible() const { return isVisible_; }
    void ToggleVisibility() { isVisible_ = !isVisible_; }

    void RefreshData();

private:
    void RenderInfiniteSynthesisTab();
    void RenderSynthesisNodesTab();
    void RenderInfiniteStreamsTab();
    void RenderSynthesisWavesTab();
    void RenderIntegrationMatrixTab();
    void RenderConvergenceTensorTab();
    void RenderInfiniteClarityTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    void RenderInfiniteSynthesisList();
    void RenderInfiniteSynthesisEditor();
    void RenderSynthesisNodeList();
    void RenderSynthesisNodeEditor();
    void RenderInfiniteStreamList();
    void RenderInfiniteStreamEditor();
    void RenderSynthesisWaveList();
    void RenderSynthesisWaveEditor();
    void RenderIntegrationMatrixList();
    void RenderIntegrationMatrixEditor();
    void RenderIntegrationMatrixVisualization();
    void RenderConvergenceTensorList();
    void RenderConvergenceTensorEditor();
    void RenderConvergenceTensorVisualization();
    void RenderInfiniteClarityList();
    void RenderInfiniteClarityEditor();

    void RenderMatrixCell(float value, int row, int col);
    void RenderTensorPlane(const InfiniteSynthesis::ConvergenceTensor& tensor, int plane);

    void CreateNewInfiniteSynthesis();
    void CreateNewSynthesisNode();
    void CreateNewInfiniteStream();
    void CreateNewSynthesisWave();
    void CreateNewIntegrationMatrix();
    void CreateNewConvergenceTensor();
    void CreateNewInfiniteClarity();

    void DeleteSelectedInfiniteSynthesis();
    void DeleteSelectedSynthesisNode();
    void DeleteSelectedInfiniteStream();
    void DeleteSelectedSynthesisWave();
    void DeleteSelectedIntegrationMatrix();
    void DeleteSelectedConvergenceTensor();
    void DeleteSelectedInfiniteClarity();

    void ApplyInfiniteSynthesisActions();
    void ApplySynthesisNodeActions();
    void ApplyIntegrationMatrixActions();

    bool isVisible_ = false;
    bool isInitialized_ = false;
    int currentTab_ = 0;

    std::string selectedInfiniteSynthesisId_;
    std::string selectedSynthesisNodeId_;
    std::string selectedInfiniteStreamId_;
    std::string selectedSynthesisWaveId_;
    std::string selectedIntegrationMatrixId_;
    std::string selectedConvergenceTensorId_;
    std::string selectedInfiniteClarityId_;

    char nameBuffer_[256];
    float synthesisValue_ = 0.5f;
    float integrationValue_ = 0.5f;
    float continuityValue_ = 0.5f;
    float omnipresenceValue_ = 0.5f;
    float harmonyValue_ = 0.5f;
    float coherenceValue_ = 0.5f;
    float clarityValue_ = 0.5f;
    float localSynthesisValue_ = 0.5f;
    float globalSynthesisValue_ = 0.5f;
    float harmonyFactorValue_ = 0.5f;
    float integrationStrengthValue_ = 0.5f;
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

    std::vector<std::shared_ptr<InfiniteSynthesis::InfiniteSynthesis>> cachedInfiniteSyntheses_;
    std::vector<std::shared_ptr<InfiniteSynthesis::SynthesisNode>> cachedSynthesisNodes_;
    std::vector<std::shared_ptr<InfiniteSynthesis::InfiniteStream>> cachedInfiniteStreams_;
    std::vector<std::shared_ptr<InfiniteSynthesis::SynthesisWave>> cachedSynthesisWaves_;
    std::vector<std::shared_ptr<InfiniteSynthesis::IntegrationMatrix>> cachedIntegrationMatrices_;
    std::vector<std::shared_ptr<InfiniteSynthesis::ConvergenceTensor>> cachedConvergenceTensors_;
    std::vector<std::shared_ptr<InfiniteSynthesis::InfiniteClarity>> cachedInfiniteClarities_;

    float refreshTimer_ = 0.0f;
    const float refreshInterval_ = 0.5f;
};

extern InfiniteSynthesisPanel g_infiniteSynthesisPanel;

} // namespace IDE
