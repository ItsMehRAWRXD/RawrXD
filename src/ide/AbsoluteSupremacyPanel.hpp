#pragma once
#include "../infinite/AbsoluteSupremacyEngine.hpp"
#include <imgui.h>
#include <string>
#include <vector>

namespace AbsoluteSupremacy {

class AbsoluteSupremacyPanel {
public:
    AbsoluteSupremacyPanel(AbsoluteSupremacyEngine& engine);
    ~AbsoluteSupremacyPanel();

    void Render();
    void ProcessHotkeys();

    bool IsVisible() const { return visible_; }
    void SetVisible(bool visible) { visible_ = visible; }
    void ToggleVisible() { visible_ = !visible_; }

private:
    void RenderSupremacyList();
    void RenderNodeEditor();
    void RenderStreamVisualizer();
    void RenderWaveAnalyzer();
    void RenderMatrixView();
    void RenderTensorView();
    void RenderClarityMonitor();
    void RenderHierarchyView();
    void RenderAuthorityPanel();
    void RenderPowerGrid();

    AbsoluteSupremacyEngine& engine_;
    bool visible_;
    int selectedTab_;
    char newSupremacyName_[256];
    char selectedSupremacyId_[64];

    // Visualization data
    std::vector<float> supremacyHistory_;
    std::vector<float> dominanceHistory_;
    std::vector<float> authorityHistory_;
    std::vector<float> powerHistory_;
    std::vector<float> controlHistory_;
    std::vector<float> masteryHistory_;
    std::vector<float> sovereigntyHistory_;
    std::vector<float> reignHistory_;
    std::vector<float> influenceHistory_;

    static constexpr int MAX_HISTORY = 300;
};

} // namespace AbsoluteSupremacy
