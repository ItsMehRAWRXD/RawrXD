#pragma once

#include "../absolute/AbsoluteUnityEngine.hpp"
#include "../absolute/AbsoluteUnityLoop.hpp"
#include <cstring>

struct ImVec2;
struct ImVec4;

namespace AbsoluteUnityIDE {

struct PanelColors {
    ImVec4 background;
    ImVec4 header;
    ImVec4 text;
    ImVec4 accent;
    ImVec4 border;
    ImVec4 hover;
    ImVec4 active;
    ImVec4 absolute;
    ImVec4 unity;
    ImVec4 harmony;
    ImVec4 continuity;
    ImVec4 omnipresence;
    ImVec4 coherence;
    ImVec4 clarity;
    ImVec4 eternity;
    ImVec4 stability;
    ImVec4 density;
    ImVec4 purity;
    ImVec4 supremacy;
    ImVec4 absoluteness;
};

struct PanelState {
    bool showAbsoluteUnities = true;
    bool showUnityNodes = true;
    bool showAbsoluteStreams = true;
    bool showUnityWaves = true;
    bool showAbsoluteMatrices = true;
    bool showAbsoluteTensors = true;
    bool showAbsoluteClarities = true;
    bool showMetrics = true;
    bool showVisualization = true;
    int selectedAbsoluteIndex = -1;
    int selectedNodeIndex = -1;
    int selectedStreamIndex = -1;
    int selectedWaveIndex = -1;
    int selectedMatrixIndex = -1;
    int selectedTensorIndex = -1;
    int selectedClarityIndex = -1;
    char newAbsoluteName[256] = "";
    char newNodeName[256] = "";
    char newStreamName[256] = "";
    char newWaveName[256] = "";
    char newMatrixName[256] = "";
    char newTensorName[256] = "";
    char newClarityName[256] = "";
    char searchFilter[256] = "";
    bool autoRefresh = true;
    float refreshRate = 1.0f;
    float lastRefreshTime = 0.0f;
    int matrixViewMode = 0;
    int tensorViewMode = 0;
    float matrixScale = 1.0f;
    float tensorScale = 1.0f;
    bool showMatrixGrid = true;
    bool showTensorGrid = true;
    int selectedMatrixCell[2] = {-1, -1};
    int selectedTensorCell[3] = {-1, -1, -1};
};

class AbsoluteUnityPanel {
public:
    AbsoluteUnityPanel();
    ~AbsoluteUnityPanel();
    
    void Initialize();
    void Shutdown();
    void Render();
    void RenderDockingLayout();
    
    void SetVisible(bool visible) { isVisible_ = visible; }
    bool IsVisible() const { return isVisible_; }
    
    void ToggleVisibility() { isVisible_ = !isVisible_; }
    
    void SetColors(const PanelColors& colors) { colors_ = colors; }
    PanelColors GetColors() const { return colors_; }
    
    void SetState(const PanelState& state) { state_ = state; }
    PanelState GetState() const { return state_; }
    
    void RefreshData();
    void ClearSelection();
    
    void SetAutoRefresh(bool enabled) { state_.autoRefresh = enabled; }
    bool IsAutoRefreshEnabled() const { return state_.autoRefresh; }
    
    void SetRefreshRate(float rate) { state_.refreshRate = rate; }
    float GetRefreshRate() const { return state_.refreshRate; }
    
    void TriggerAbsoluteResonance();
    void TriggerUnityResonance();
    void TriggerConvergenceResonance();
    void TriggerContinuityResonance();
    void TriggerOmnipresenceResonance();
    void TriggerCoherenceResonance();
    void TriggerClarityResonance();
    void TriggerHarmonyResonance();
    void TriggerStabilityResonance();
    void TriggerDensityResonance();
    void TriggerPurityResonance();
    void TriggerEternityResonance();
    void TriggerSupremacyResonance();
    void TriggerAbsolutenessResonance();
    
    void RequestSyncPulse();
    void RequestHarmonyPulse();
    
private:
    void RenderAbsoluteUnitiesTab();
    void RenderUnityNodesTab();
    void RenderAbsoluteStreamsTab();
    void RenderUnityWavesTab();
    void RenderAbsoluteMatricesTab();
    void RenderAbsoluteTensorsTab();
    void RenderAbsoluteClaritiesTab();
    void RenderMetricsTab();
    void RenderVisualizationTab();
    
    void RenderAbsoluteUnityList();
    void RenderAbsoluteUnityDetails();
    void RenderUnityNodeList();
    void RenderUnityNodeDetails();
    void RenderAbsoluteStreamList();
    void RenderAbsoluteStreamDetails();
    void RenderUnityWaveList();
    void RenderUnityWaveDetails();
    void RenderAbsoluteMatrixList();
    void RenderAbsoluteMatrixDetails();
    void RenderAbsoluteMatrixVisualization();
    void RenderAbsoluteTensorList();
    void RenderAbsoluteTensorDetails();
    void RenderAbsoluteTensorVisualization();
    void RenderAbsoluteClarityList();
    void RenderAbsoluteClarityDetails();
    
    void RenderMetricsOverview();
    void RenderPerformanceMetrics();
    void RenderResonanceMetrics();
    void RenderSyncStatus();
    
    void RenderCreateAbsoluteUnityDialog();
    void RenderCreateUnityNodeDialog();
    void RenderCreateAbsoluteStreamDialog();
    void RenderCreateUnityWaveDialog();
    void RenderCreateAbsoluteMatrixDialog();
    void RenderCreateAbsoluteTensorDialog();
    void RenderCreateAbsoluteClarityDialog();
    
    void RenderToolbar();
    void RenderStatusBar();
    void RenderSearchBar();
    
    void ApplyAbsoluteTheme();
    void RenderAbsoluteBackground();
    
    bool isVisible_ = true;
    bool isInitialized_ = false;
    PanelColors colors_;
    PanelState state_;
    
    std::vector<std::shared_ptr<AbsoluteUnity::AbsoluteUnity>> absoluteUnities_;
    std::vector<std::shared_ptr<AbsoluteUnity::UnityNode>> nodes_;
    std::vector<std::shared_ptr<AbsoluteUnity::AbsoluteStream>> streams_;
    std::vector<std::shared_ptr<AbsoluteUnity::UnityWave>> waves_;
    std::vector<std::shared_ptr<AbsoluteUnity::AbsoluteMatrix>> matrices_;
    std::vector<std::shared_ptr<AbsoluteUnity::AbsoluteTensor>> tensors_;
    std::vector<std::shared_ptr<AbsoluteUnity::AbsoluteClarity>> clarities_;
    AbsoluteUnity::AbsoluteUnityMetrics metrics_;
    
    mutable std::mutex dataMutex_;
};

} // namespace AbsoluteUnityIDE
