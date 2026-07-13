#pragma once

#include "../supreme/SupremeHarmonyEngine.hpp"
#include "../supreme/SupremeHarmonyLoop.hpp"
#include <cstring>

struct ImVec2;
struct ImVec4;

namespace SupremeHarmonyIDE {

struct PanelColors {
    ImVec4 background;
    ImVec4 header;
    ImVec4 text;
    ImVec4 accent;
    ImVec4 border;
    ImVec4 hover;
    ImVec4 active;
    ImVec4 supreme;
    ImVec4 harmony;
    ImVec4 unity;
    ImVec4 continuity;
    ImVec4 omnipresence;
    ImVec4 coherence;
    ImVec4 clarity;
    ImVec4 eternity;
    ImVec4 stability;
    ImVec4 density;
    ImVec4 purity;
    ImVec4 supremacy;
};

struct PanelState {
    bool showSupremeHarmonies = true;
    bool showHarmonyNodes = true;
    bool showSupremeStreams = true;
    bool showHarmonyWaves = true;
    bool showSupremeMatrices = true;
    bool showSupremeTensors = true;
    bool showSupremeClarities = true;
    bool showMetrics = true;
    bool showVisualization = true;
    int selectedSupremeIndex = -1;
    int selectedNodeIndex = -1;
    int selectedStreamIndex = -1;
    int selectedWaveIndex = -1;
    int selectedMatrixIndex = -1;
    int selectedTensorIndex = -1;
    int selectedClarityIndex = -1;
    char newSupremeName[256] = "";
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

class SupremeHarmonyPanel {
public:
    SupremeHarmonyPanel();
    ~SupremeHarmonyPanel();
    
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
    
    void TriggerSupremeResonance();
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
    
    void RequestSyncPulse();
    void RequestHarmonyPulse();
    
private:
    void RenderSupremeHarmoniesTab();
    void RenderHarmonyNodesTab();
    void RenderSupremeStreamsTab();
    void RenderHarmonyWavesTab();
    void RenderSupremeMatricesTab();
    void RenderSupremeTensorsTab();
    void RenderSupremeClaritiesTab();
    void RenderMetricsTab();
    void RenderVisualizationTab();
    
    void RenderSupremeHarmonyList();
    void RenderSupremeHarmonyDetails();
    void RenderHarmonyNodeList();
    void RenderHarmonyNodeDetails();
    void RenderSupremeStreamList();
    void RenderSupremeStreamDetails();
    void RenderHarmonyWaveList();
    void RenderHarmonyWaveDetails();
    void RenderSupremeMatrixList();
    void RenderSupremeMatrixDetails();
    void RenderSupremeMatrixVisualization();
    void RenderSupremeTensorList();
    void RenderSupremeTensorDetails();
    void RenderSupremeTensorVisualization();
    void RenderSupremeClarityList();
    void RenderSupremeClarityDetails();
    
    void RenderMetricsOverview();
    void RenderPerformanceMetrics();
    void RenderResonanceMetrics();
    void RenderSyncStatus();
    
    void RenderCreateSupremeHarmonyDialog();
    void RenderCreateHarmonyNodeDialog();
    void RenderCreateSupremeStreamDialog();
    void RenderCreateHarmonyWaveDialog();
    void RenderCreateSupremeMatrixDialog();
    void RenderCreateSupremeTensorDialog();
    void RenderCreateSupremeClarityDialog();
    
    void RenderToolbar();
    void RenderStatusBar();
    void RenderSearchBar();
    
    void ApplySupremeTheme();
    void RenderSupremeBackground();
    
    bool isVisible_ = true;
    bool isInitialized_ = false;
    PanelColors colors_;
    PanelState state_;
    
    std::vector<std::shared_ptr<SupremeHarmony::SupremeHarmony>> supremeHarmonies_;
    std::vector<std::shared_ptr<SupremeHarmony::HarmonyNode>> nodes_;
    std::vector<std::shared_ptr<SupremeHarmony::SupremeStream>> streams_;
    std::vector<std::shared_ptr<SupremeHarmony::HarmonyWave>> waves_;
    std::vector<std::shared_ptr<SupremeHarmony::SupremeMatrix>> matrices_;
    std::vector<std::shared_ptr<SupremeHarmony::SupremeTensor>> tensors_;
    std::vector<std::shared_ptr<SupremeHarmony::SupremeClarity>> clarities_;
    SupremeHarmony::SupremeHarmonyMetrics metrics_;
    
    mutable std::mutex dataMutex_;
};

} // namespace SupremeHarmonyIDE
