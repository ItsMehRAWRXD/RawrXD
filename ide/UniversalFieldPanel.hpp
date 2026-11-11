#pragma once

#include "universal/UniversalFieldEngine.hpp"
#include <string>
#include <vector>
#include <memory>

// Forward declaration for ImGui
struct ImVec2;

namespace IDE {

// Panel for managing Universal Field (Layer 118)
class UniversalFieldPanel {
public:
    UniversalFieldPanel();
    ~UniversalFieldPanel();

    // Initialize the panel
    void Initialize();
    void Shutdown();

    // Render the panel
    void Render();

    // Visibility
    void SetVisible(bool visible);
    bool IsVisible() const { return isVisible_; }
    void ToggleVisibility() { isVisible_ = !isVisible_; }

    // Refresh data
    void RefreshData();

private:
    void RenderUniversalFieldTab();
    void RenderFieldNodesTab();
    void RenderUniversalStreamsTab();
    void RenderFieldWavesTab();
    void RenderHarmonyMatrixTab();
    void RenderUnityTensorTab();
    void RenderUniversalClarityTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Helper methods
    void RenderUniversalFieldList();
    void RenderUniversalFieldEditor();
    void RenderFieldNodeList();
    void RenderFieldNodeEditor();
    void RenderUniversalStreamList();
    void RenderUniversalStreamEditor();
    void RenderFieldWaveList();
    void RenderFieldWaveEditor();
    void RenderHarmonyMatrixList();
    void RenderHarmonyMatrixEditor();
    void RenderHarmonyMatrixVisualization();
    void RenderUnityTensorList();
    void RenderUnityTensorEditor();
    void RenderUnityTensorVisualization();
    void RenderUniversalClarityList();
    void RenderUniversalClarityEditor();

    // Matrix/Tensor visualization helpers
    void RenderMatrixCell(float value, int row, int col);
    void RenderTensorPlane(const UniversalField::UnityTensor& tensor, int plane);

    // Actions
    void CreateNewUniversalField();
    void CreateNewFieldNode();
    void CreateNewUniversalStream();
    void CreateNewFieldWave();
    void CreateNewHarmonyMatrix();
    void CreateNewUnityTensor();
    void CreateNewUniversalClarity();

    void DeleteSelectedUniversalField();
    void DeleteSelectedFieldNode();
    void DeleteSelectedUniversalStream();
    void DeleteSelectedFieldWave();
    void DeleteSelectedHarmonyMatrix();
    void DeleteSelectedUnityTensor();
    void DeleteSelectedUniversalClarity();

    void ApplyUniversalFieldActions();
    void ApplyFieldNodeActions();
    void ApplyHarmonyMatrixActions();

    // State
    bool isVisible_ = false;
    bool isInitialized_ = false;

    // Tab state
    int currentTab_ = 0;

    // Selection state
    std::string selectedUniversalFieldId_;
    std::string selectedFieldNodeId_;
    std::string selectedUniversalStreamId_;
    std::string selectedFieldWaveId_;
    std::string selectedHarmonyMatrixId_;
    std::string selectedUnityTensorId_;
    std::string selectedUniversalClarityId_;

    // Editor state
    char nameBuffer_[256];
    float universalityValue_ = 0.5f;
    float permeationValue_ = 0.5f;
    float continuityValue_ = 0.5f;
    float omnipresenceValue_ = 0.5f;
    float harmonyValue_ = 0.5f;
    float coherenceValue_ = 0.5f;
    float clarityValue_ = 0.5f;
    float unityValue_ = 0.5f;
    float purityValue_ = 0.5f;
    float streamFlowValue_ = 0.5f;
    float densityValue_ = 0.5f;
    float amplitudeValue_ = 0.5f;
    float frequencyValue_ = 0.5f;
    float localUniversalityValue_ = 0.5f;
    float globalUniversalityValue_ = 0.5f;
    float harmonyFactorValue_ = 0.5f;
    float permeationStrengthValue_ = 0.5f;
    bool isUnified_ = false;
    bool isActive_ = true;

    // Metrics display
    float displayTPS_ = 0.0f;
    float displayFPS_ = 0.0f;
    uint64_t displayTickCount_ = 0;
    uint64_t displayFrameCount_ = 0;
    uint64_t displaySyncCount_ = 0;
    uint64_t displayHarmonyCount_ = 0;

    // Settings
    float targetTPS_ = 60.0f;
    float maxFPS_ = 60.0f;
    bool enableFrameLimiting_ = true;
    bool enableMetrics_ = true;
    bool enableOmnipresentTickPropagation_ = true;
    bool enableMultiLayerSynchronization_ = true;
    bool enableCrossLayerHarmonyHarmonization_ = true;
    float syncIntervalMs_ = 100.0f;
    float harmonyIntervalMs_ = 100.0f;

    // Data cache
    std::vector<std::shared_ptr<UniversalField::UniversalField>> cachedUniversalFields_;
    std::vector<std::shared_ptr<UniversalField::FieldNode>> cachedFieldNodes_;
    std::vector<std::shared_ptr<UniversalField::UniversalStream>> cachedUniversalStreams_;
    std::vector<std::shared_ptr<UniversalField::FieldWave>> cachedFieldWaves_;
    std::vector<std::shared_ptr<UniversalField::HarmonyMatrix>> cachedHarmonyMatrices_;
    std::vector<std::shared_ptr<UniversalField::UnityTensor>> cachedUnityTensors_;
    std::vector<std::shared_ptr<UniversalField::UniversalClarity>> cachedUniversalClarities_;

    // Refresh timer
    float refreshTimer_ = 0.0f;
    const float refreshInterval_ = 0.5f; // Refresh every 0.5 seconds
};

// Global panel instance
extern UniversalFieldPanel g_universalFieldPanel;

} // namespace IDE
