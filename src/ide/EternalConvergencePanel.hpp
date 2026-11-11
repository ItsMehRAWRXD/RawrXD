#pragma once

#include "../eternal/EternalConvergenceEngine.hpp"
#include "../eternal/EternalConvergenceLoop.hpp"
#include <string>

struct ImVec2;
struct ImVec4;

namespace EternalConvergenceIDE {

struct PanelColors {
    ImVec4 background;
    ImVec4 header;
    ImVec4 text;
    ImVec4 accent;
    ImVec4 border;
    ImVec4 hover;
    ImVec4 active;
    ImVec4 eternal;
    ImVec4 convergence;
    ImVec4 unity;
    ImVec4 continuity;
    ImVec4 omnipresence;
    ImVec4 coherence;
    ImVec4 clarity;
    ImVec4 harmony;
    ImVec4 stability;
    ImVec4 density;
    ImVec4 purity;
    ImVec4 eternity;
};

struct PanelState {
    bool showEternalConvergences = true;
    bool showConvergenceNodes = true;
    bool showEternalStreams = true;
    bool showConvergenceWaves = true;
    bool showUnityMatrices = true;
    bool showEternalTensors = true;
    bool showEternalClarities = true;
    bool showMetrics = true;
    bool showVisualization = true;
    int selectedEternalIndex = -1;
    int selectedNodeIndex = -1;
    int selectedStreamIndex = -1;
    int selectedWaveIndex = -1;
    int selectedMatrixIndex = -1;
    int selectedTensorIndex = -1;
    int selectedClarityIndex = -1;
    char newEternalName[256] = "";
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

class EternalConvergencePanel {
public:
    EternalConvergencePanel();
    ~EternalConvergencePanel();
    
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
    
    void TriggerEternalResonance();
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
    
    void RequestSyncPulse();
    void RequestHarmonyPulse();
    
private:
    void RenderEternalConvergencesTab();
    void RenderConvergenceNodesTab();
    void RenderEternalStreamsTab();
    void RenderConvergenceWavesTab();
    void RenderUnityMatricesTab();
    void RenderEternalTensorsTab();
    void RenderEternalClaritiesTab();
    void RenderMetricsTab();
    void RenderVisualizationTab();
    
    void RenderEternalConvergenceList();
    void RenderEternalConvergenceDetails();
    void RenderConvergenceNodeList();
    void RenderConvergenceNodeDetails();
    void RenderEternalStreamList();
    void RenderEternalStreamDetails();
    void RenderConvergenceWaveList();
    void RenderConvergenceWaveDetails();
    void RenderUnityMatrixList();
    void RenderUnityMatrixDetails();
    void RenderUnityMatrixVisualization();
    void RenderEternalTensorList();
    void RenderEternalTensorDetails();
    void RenderEternalTensorVisualization();
    void RenderEternalClarityList();
    void RenderEternalClarityDetails();
    
    void RenderMetricsOverview();
    void RenderPerformanceMetrics();
    void RenderResonanceMetrics();
    void RenderSyncStatus();
    
    void RenderCreateEternalConvergenceDialog();
    void RenderCreateConvergenceNodeDialog();
    void RenderCreateEternalStreamDialog();
    void RenderCreateConvergenceWaveDialog();
    void RenderCreateUnityMatrixDialog();
    void RenderCreateEternalTensorDialog();
    void RenderCreateEternalClarityDialog();
    
    void RenderToolbar();
    void RenderStatusBar();
    void RenderSearchBar();
    
    void ApplyEternalTheme();
    void RenderEternalBackground();
    
    bool isVisible_ = true;
    bool isInitialized_ = false;
    PanelColors colors_;
    PanelState state_;
    
    std::vector<std::shared_ptr<EternalConvergence::EternalConvergence>> eternalConvergences_;
    std::vector<std::shared_ptr<EternalConvergence::ConvergenceNode>> nodes_;
    std::vector<std::shared_ptr<EternalConvergence::EternalStream>> streams_;
    std::vector<std::shared_ptr<EternalConvergence::ConvergenceWave>> waves_;
    std::vector<std::shared_ptr<EternalConvergence::UnityMatrix>> matrices_;
    std::vector<std::shared_ptr<EternalConvergence::EternalTensor>> tensors_;
    std::vector<std::shared_ptr<EternalConvergence::EternalClarity>> clarities_;
    EternalConvergence::EternalConvergenceMetrics metrics_;
    
    mutable std::mutex dataMutex_;
};

} // namespace EternalConvergenceIDE
