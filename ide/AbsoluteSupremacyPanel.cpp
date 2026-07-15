#include "AbsoluteSupremacyPanel.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>

namespace AbsoluteSupremacy {

AbsoluteSupremacyPanel::AbsoluteSupremacyPanel(AbsoluteSupremacyEngine& engine)
    : engine_(engine), visible_(false), selectedTab_(0) {
    memset(newSupremacyName_, 0, sizeof(newSupremacyName_));
    memset(selectedSupremacyId_, 0, sizeof(selectedSupremacyId_));
    supremacyHistory_.reserve(MAX_HISTORY);
    dominanceHistory_.reserve(MAX_HISTORY);
    authorityHistory_.reserve(MAX_HISTORY);
    powerHistory_.reserve(MAX_HISTORY);
    controlHistory_.reserve(MAX_HISTORY);
    masteryHistory_.reserve(MAX_HISTORY);
    sovereigntyHistory_.reserve(MAX_HISTORY);
    reignHistory_.reserve(MAX_HISTORY);
    influenceHistory_.reserve(MAX_HISTORY);
}

AbsoluteSupremacyPanel::~AbsoluteSupremacyPanel() {}

void AbsoluteSupremacyPanel::Render() {
    if (!visible_) return;

    ImGui::Begin("Absolute Supremacy (Layer 125)", &visible_, ImGuiWindowFlags_MenuBar);

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("Actions")) {
            if (ImGui::MenuItem("Create New Supremacy")) {
                std::string id = engine_.CreateAbsoluteSupremacy();
                strncpy(selectedSupremacyId_, id.c_str(), sizeof(selectedSupremacyId_) - 1);
            }
            if (ImGui::MenuItem("Refresh")) {}
            ImGui::Separator();
            if (ImGui::MenuItem("Close")) {
                visible_ = false;
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    // Tab bar
    if (ImGui::BeginTabBar("SupremacyTabs", ImGuiTabBarFlags_Reorderable)) {
        if (ImGui::BeginTabItem("Supremacies")) {
            selectedTab_ = 0;
            RenderSupremacyList();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Nodes")) {
            selectedTab_ = 1;
            RenderNodeEditor();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Streams")) {
            selectedTab_ = 2;
            RenderStreamVisualizer();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Waves")) {
            selectedTab_ = 3;
            RenderWaveAnalyzer();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Matrix")) {
            selectedTab_ = 4;
            RenderMatrixView();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Tensor")) {
            selectedTab_ = 5;
            RenderTensorView();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Clarity")) {
            selectedTab_ = 6;
            RenderClarityMonitor();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Hierarchy")) {
            selectedTab_ = 7;
            RenderHierarchyView();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Authority")) {
            selectedTab_ = 8;
            RenderAuthorityPanel();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Power Grid")) {
            selectedTab_ = 9;
            RenderPowerGrid();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}

void AbsoluteSupremacyPanel::RenderSupremacyList() {
    ImGui::Text("Absolute Supremacy Entities");
    ImGui::Separator();

    auto supremacies = engine_.ListAbsoluteSupremacies();

    // Create new section
    ImGui::InputText("New Supremacy Name", newSupremacyName_, sizeof(newSupremacyName_));
    if (ImGui::Button("Create")) {
        std::string id = engine_.CreateAbsoluteSupremacy();
        strncpy(selectedSupremacyId_, id.c_str(), sizeof(selectedSupremacyId_) - 1);
        memset(newSupremacyName_, 0, sizeof(newSupremacyName_));
    }

    ImGui::Separator();

    // List existing supremacies
    ImGui::BeginChild("SupremacyList", ImVec2(300, 300), true);
    for (const auto& id : supremacies) {
        auto sup = engine_.ReadAbsoluteSupremacy(id);
        if (!sup) continue;

        bool isSelected = (strcmp(selectedSupremacyId_, id.c_str()) == 0);
        if (ImGui::Selectable(id.c_str(), isSelected)) {
            strncpy(selectedSupremacyId_, id.c_str(), sizeof(selectedSupremacyId_) - 1);
        }

        if (isSelected) {
            ImGui::Indent();
            ImGui::Text("Supremacy: %.3f", sup->supremacy);
            ImGui::Text("Dominance: %.3f", sup->dominance);
            ImGui::Text("Authority: %.3f", sup->authority);
            ImGui::Text("Power: %.3f", sup->power);
            ImGui::Text("Control: %.3f", sup->control);
            ImGui::Text("Mastery: %.3f", sup->mastery);
            ImGui::Text("Sovereignty: %.3f", sup->sovereignty);
            ImGui::Text("Reign: %.3f", sup->reign);
            ImGui::Text("Command: %.3f", sup->command);
            ImGui::Text("Influence: %.3f", sup->influence);
            ImGui::Unindent();
        }
    }
    ImGui::EndChild();

    // History plots
    if (!supremacies.empty()) {
        auto first = engine_.ReadAbsoluteSupremacy(supremacies[0]);
        if (first) {
            supremacyHistory_.push_back((float)first->supremacy);
            dominanceHistory_.push_back((float)first->dominance);
            authorityHistory_.push_back((float)first->authority);
            powerHistory_.push_back((float)first->power);
            controlHistory_.push_back((float)first->control);
            masteryHistory_.push_back((float)first->mastery);
            sovereigntyHistory_.push_back((float)first->sovereignty);
            reignHistory_.push_back((float)first->reign);
            influenceHistory_.push_back((float)first->influence);

            if (supremacyHistory_.size() > MAX_HISTORY) supremacyHistory_.erase(supremacyHistory_.begin());
            if (dominanceHistory_.size() > MAX_HISTORY) dominanceHistory_.erase(dominanceHistory_.begin());
            if (authorityHistory_.size() > MAX_HISTORY) authorityHistory_.erase(authorityHistory_.begin());
            if (powerHistory_.size() > MAX_HISTORY) powerHistory_.erase(powerHistory_.begin());
            if (controlHistory_.size() > MAX_HISTORY) controlHistory_.erase(controlHistory_.begin());
            if (masteryHistory_.size() > MAX_HISTORY) masteryHistory_.erase(masteryHistory_.begin());
            if (sovereigntyHistory_.size() > MAX_HISTORY) sovereigntyHistory_.erase(sovereigntyHistory_.begin());
            if (reignHistory_.size() > MAX_HISTORY) reignHistory_.erase(reignHistory_.begin());
            if (influenceHistory_.size() > MAX_HISTORY) influenceHistory_.erase(influenceHistory_.begin());

            ImGui::PlotLines("Supremacy", supremacyHistory_.data(), (int)supremacyHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Dominance", dominanceHistory_.data(), (int)dominanceHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Authority", authorityHistory_.data(), (int)authorityHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Power", powerHistory_.data(), (int)powerHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Control", controlHistory_.data(), (int)controlHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Mastery", masteryHistory_.data(), (int)masteryHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Sovereignty", sovereigntyHistory_.data(), (int)sovereigntyHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Reign", reignHistory_.data(), (int)reignHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
            ImGui::PlotLines("Influence", influenceHistory_.data(), (int)influenceHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 80));
        }
    }
}

void AbsoluteSupremacyPanel::RenderNodeEditor() {
    ImGui::Text("Supremacy Node Editor");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    auto nodes = engine_.ListSupremacyNodes(selectedSupremacyId_);

    ImGui::Text("Nodes for: %s", selectedSupremacyId_);

    if (ImGui::Button("Create Node")) {
        engine_.CreateSupremacyNode(selectedSupremacyId_);
    }

    ImGui::BeginChild("NodeList", ImVec2(0, 300), true);
    for (const auto& nodeId : nodes) {
        auto node = engine_.ReadSupremacyNode(nodeId);
        if (!node) continue;

        ImGui::Text("Node: %s", nodeId.c_str());
        ImGui::Indent();
        ImGui::SliderFloat("Local Supremacy", (float*)&node->localSupremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Global Supremacy", (float*)&node->globalSupremacy, 0.0f, 1.0f);
        ImGui::SliderFloat("Dominance Level", (float*)&node->dominanceLevel, 0.0f, 1.0f);
        ImGui::SliderFloat("Authority Index", (float*)&node->authorityIndex, 0.0f, 1.0f);
        ImGui::SliderFloat("Power Level", (float*)&node->powerLevel, 0.0f, 1.0f);
        ImGui::SliderFloat("Control Factor", (float*)&node->controlFactor, 0.0f, 1.0f);
        ImGui::SliderFloat("Mastery Level", (float*)&node->masteryLevel, 0.0f, 1.0f);
        if (ImGui::Button("Delete")) {
            engine_.DeleteSupremacyNode(nodeId);
        }
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void AbsoluteSupremacyPanel::RenderStreamVisualizer() {
    ImGui::Text("Supremacy Stream Visualizer");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    auto streams = engine_.ListSupremacyStreams(selectedSupremacyId_);

    if (ImGui::Button("Create Stream")) {
        engine_.CreateSupremacyStream(selectedSupremacyId_);
    }

    ImGui::BeginChild("StreamList", ImVec2(0, 400), true);
    for (const auto& streamId : streams) {
        auto stream = engine_.ReadSupremacyStream(streamId);
        if (!stream) continue;

        ImGui::Text("Stream: %s", streamId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)stream->streamFlow, ImVec2(-1, 0), "Flow");
        ImGui::ProgressBar((float)stream->streamVelocity, ImVec2(-1, 0), "Velocity");
        ImGui::ProgressBar((float)stream->streamDensity, ImVec2(-1, 0), "Density");
        ImGui::ProgressBar((float)stream->streamPower, ImVec2(-1, 0), "Power");
        ImGui::ProgressBar((float)stream->streamControl, ImVec2(-1, 0), "Control");
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void AbsoluteSupremacyPanel::RenderWaveAnalyzer() {
    ImGui::Text("Supremacy Wave Analyzer");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    auto waves = engine_.ListSupremacyWaves(selectedSupremacyId_);

    if (ImGui::Button("Create Wave")) {
        engine_.CreateSupremacyWave(selectedSupremacyId_);
    }

    ImGui::BeginChild("WaveList", ImVec2(0, 400), true);
    for (const auto& waveId : waves) {
        auto wave = engine_.ReadSupremacyWave(waveId);
        if (!wave) continue;

        ImGui::Text("Wave: %s", waveId.c_str());
        ImGui::Indent();
        ImGui::SliderFloat("Frequency", (float*)&wave->frequency, 0.0f, 2.0f);
        ImGui::SliderFloat("Amplitude", (float*)&wave->amplitude, 0.0f, 1.0f);
        ImGui::SliderFloat("Phase", (float*)&wave->phase, 0.0f, 6.28f);
        ImGui::ProgressBar((float)wave->resonance, ImVec2(-1, 0), "Resonance");
        ImGui::ProgressBar((float)wave->dominance, ImVec2(-1, 0), "Dominance");
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void AbsoluteSupremacyPanel::RenderMatrixView() {
    ImGui::Text("Supremacy Matrix (14x14)");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    auto matrices = engine_.ListSupremacyMatrices(selectedSupremacyId_);

    if (ImGui::Button("Create Matrix")) {
        engine_.CreateSupremacyMatrix(selectedSupremacyId_);
    }

    for (const auto& matrixId : matrices) {
        auto matrix = engine_.ReadSupremacyMatrix(matrixId);
        if (!matrix) continue;

        ImGui::Text("Matrix: %s", matrixId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)matrix->coherence, ImVec2(-1, 0), "Coherence");
        ImGui::ProgressBar((float)matrix->stability, ImVec2(-1, 0), "Stability");
        ImGui::ProgressBar((float)matrix->dominance, ImVec2(-1, 0), "Dominance");

        // Visual matrix representation
        ImGui::Text("Matrix Visualization:");
        ImGui::BeginChild("MatrixVis", ImVec2(280, 280), true);
        for (int i = 0; i < 14 && i < (int)matrix->matrix.size(); i++) {
            for (int j = 0; j < 14 && j < (int)matrix->matrix[i].size(); j++) {
                float val = (float)matrix->matrix[i][j];
                ImU32 color = ImGui::GetColorU32(ImVec4(val, val * 0.5f, val * 0.2f, 1.0f));
                ImVec2 pos = ImGui::GetCursorScreenPos();
                ImVec2 size(18, 18);
                ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), color);
                ImGui::Dummy(size);
                ImGui::SameLine(0, 2);
            }
            ImGui::NewLine();
        }
        ImGui::EndChild();
        ImGui::Unindent();
    }
}

void AbsoluteSupremacyPanel::RenderTensorView() {
    ImGui::Text("Supremacy Tensor (11x11x11)");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    auto tensors = engine_.ListSupremacyTensors(selectedSupremacyId_);

    if (ImGui::Button("Create Tensor")) {
        engine_.CreateSupremacyTensor(selectedSupremacyId_);
    }

    for (const auto& tensorId : tensors) {
        auto tensor = engine_.ReadSupremacyTensor(tensorId);
        if (!tensor) continue;

        ImGui::Text("Tensor: %s", tensorId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)tensor->harmony, ImVec2(-1, 0), "Harmony");
        ImGui::ProgressBar((float)tensor->eternity, ImVec2(-1, 0), "Eternity");
        ImGui::ProgressBar((float)tensor->supremacy, ImVec2(-1, 0), "Supremacy");
        ImGui::Text("Dimensions: 11x11x11");
        ImGui::Unindent();
    }
}

void AbsoluteSupremacyPanel::RenderClarityMonitor() {
    ImGui::Text("Supremacy Clarity Monitor");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    auto clarities = engine_.ListSupremacyClarities(selectedSupremacyId_);

    if (ImGui::Button("Create Clarity")) {
        engine_.CreateSupremacyClarity(selectedSupremacyId_);
    }

    ImGui::BeginChild("ClarityList", ImVec2(0, 400), true);
    for (const auto& clarityId : clarities) {
        auto clarity = engine_.ReadSupremacyClarity(clarityId);
        if (!clarity) continue;

        ImGui::Text("Clarity: %s", clarityId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)clarity->clarity, ImVec2(-1, 0), "Clarity");
        ImGui::ProgressBar((float)clarity->purity, ImVec2(-1, 0), "Purity");
        ImGui::ProgressBar((float)clarity->coherence, ImVec2(-1, 0), "Coherence");
        ImGui::ProgressBar((float)clarity->resonance, ImVec2(-1, 0), "Resonance");
        ImGui::ProgressBar((float)clarity->dominance, ImVec2(-1, 0), "Dominance");
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void AbsoluteSupremacyPanel::RenderHierarchyView() {
    ImGui::Text("Hierarchical Supremacy (Batch 119)");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    static int hierarchyDepth = 5;
    ImGui::SliderInt("Hierarchy Depth", &hierarchyDepth, 1, 10);

    if (ImGui::Button("Create Hierarchy")) {
        engine_.CreateHierarchy(selectedSupremacyId_, hierarchyDepth);
    }

    ImGui::Text("Hierarchy visualization shows authority flow");
    ImGui::Text("from top-level supremacy down through");
    ImGui::Text("subordinate levels.");
}

void AbsoluteSupremacyPanel::RenderAuthorityPanel() {
    ImGui::Text("Command Authority (Batch 120)");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    static char directiveText[256] = "";
    static float authorityLevel = 0.8f;

    ImGui::InputText("Directive", directiveText, sizeof(directiveText));
    ImGui::SliderFloat("Authority Level", &authorityLevel, 0.0f, 1.0f);

    if (ImGui::Button("Issue Directive")) {
        engine_.IssueDirective(selectedSupremacyId_, directiveText, authorityLevel);
    }

    ImGui::Text("Directives propagate authority through");
    ImGui::Text("the supremacy hierarchy, executing");
    ImGui::Text("commands with calculated obedience.");
}

void AbsoluteSupremacyPanel::RenderPowerGrid() {
    ImGui::Text("Power Distribution Grid (Batch 121)");
    ImGui::Separator();

    if (strlen(selectedSupremacyId_) == 0) {
        ImGui::Text("Select a supremacy entity first");
        return;
    }

    if (ImGui::Button("Create Power Grid")) {
        engine_.CreatePowerGrid(selectedSupremacyId_);
    }

    ImGui::Text("Power Grid distributes supremacy energy");
    ImGui::Text("across connected nodes, maintaining");
    ImGui::Text("grid stability and efficiency.");
}

void AbsoluteSupremacyPanel::ProcessHotkeys() {
    // Ctrl+Shift+F125 to toggle
    if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) &&
        ImGui::IsKeyDown(ImGuiKey_LeftShift) &&
        ImGui::IsKeyPressed(ImGuiKey_F12, false)) {
        ToggleVisible();
    }
}

} // namespace AbsoluteSupremacy
