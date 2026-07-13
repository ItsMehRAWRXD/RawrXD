#pragma once
#include "../infinite/EternalContinuityEngine.hpp"
#include <imgui.h>
#include <cstring>
#include <vector>

namespace EternalContinuity {

class EternalContinuityPanel {
public:
    EternalContinuityPanel(EternalContinuityEngine& engine);
    ~EternalContinuityPanel();

    void Render();
    void ProcessHotkeys();

    bool IsVisible() const { return visible_; }
    void SetVisible(bool visible) { visible_ = visible; }
    void ToggleVisible() { visible_ = !visible_; }

private:
    void RenderContinuityList();
    void RenderNodeEditor();
    void RenderStreamVisualizer();
    void RenderWaveAnalyzer();
    void RenderMatrixView();
    void RenderTensorView();
    void RenderClarityMonitor();
    void RenderPersistenceView();
    void RenderEnduranceView();
    void RenderResilienceView();

    EternalContinuityEngine& engine_;
    bool visible_;
    int selectedTab_;
    char newContinuityName_[256];
    char selectedContinuityId_[64];

    // Visualization data
    std::vector<float> eternityHistory_;
    std::vector<float> persistenceHistory_;
    std::vector<float> enduranceHistory_;
    std::vector<float> resilienceHistory_;
    std::vector<float> permanenceHistory_;
    std::vector<float> immortalityHistory_;
    std::vector<float> timelessnessHistory_;
    std::vector<float> indestructibilityHistory_;
    std::vector<float> perpetuityHistory_;
    std::vector<float> sustainabilityHistory_;

    static constexpr int MAX_HISTORY = 300;
};

} // namespace EternalContinuity
