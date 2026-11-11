#include "EternalContinuityPanel.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>

namespace EternalContinuity {

EternalContinuityPanel::EternalContinuityPanel(EternalContinuityEngine& engine)
    : engine_(engine), visible_(false), selectedTab_(0) {
    memset(newContinuityName_, 0, sizeof(newContinuityName_));
    memset(selectedContinuityId_, 0, sizeof(selectedContinuityId_));
    eternityHistory_.reserve(MAX_HISTORY);
    persistenceHistory_.reserve(MAX_HISTORY);
    enduranceHistory_.reserve(MAX_HISTORY);
    resilienceHistory_.reserve(MAX_HISTORY);
    permanenceHistory_.reserve(MAX_HISTORY);
    immortalityHistory_.reserve(MAX_HISTORY);
    timelessnessHistory_.reserve(MAX_HISTORY);
    indestructibilityHistory_.reserve(MAX_HISTORY);
    perpetuityHistory_.reserve(MAX_HISTORY);
    sustainabilityHistory_.reserve(MAX_HISTORY);
}

EternalContinuityPanel::~EternalContinuityPanel() {}

void EternalContinuityPanel::Render() {
    if (!visible_) return;

    ImGui::Begin("Eternal Continuity (Layer 126)", &visible_, ImGuiWindowFlags_MenuBar);

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("Actions")) {
            if (ImGui::MenuItem("Create New Continuity")) {
                std::string id = engine_.CreateEternalContinuity();
                strncpy(selectedContinuityId_, id.c_str(), sizeof(selectedContinuityId_) - 1);
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
    if (ImGui::BeginTabBar("ContinuityTabs", ImGuiTabBarFlags_Reorderable)) {
        if (ImGui::BeginTabItem("Continuities")) {
            selectedTab_ = 0;
            RenderContinuityList();
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
        if (ImGui::BeginTabItem("Persistence")) {
            selectedTab_ = 7;
            RenderPersistenceView();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Endurance")) {
            selectedTab_ = 8;
            RenderEnduranceView();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Resilience")) {
            selectedTab_ = 9;
            RenderResilienceView();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
}

void EternalContinuityPanel::RenderContinuityList() {
    ImGui::Text("Eternal Continuity Entities");
    ImGui::Separator();

    auto continuities = engine_.ListEternalContinuities();

    // Create new section
    ImGui::InputText("New Continuity Name", newContinuityName_, sizeof(newContinuityName_));
    if (ImGui::Button("Create")) {
        std::string id = engine_.CreateEternalContinuity();
        strncpy(selectedContinuityId_, id.c_str(), sizeof(selectedContinuityId_) - 1);
        memset(newContinuityName_, 0, sizeof(newContinuityName_));
    }

    ImGui::Separator();

    // List existing continuities
    ImGui::BeginChild("ContinuityList", ImVec2(300, 300), true);
    for (const auto& id : continuities) {
        auto cont = engine_.ReadEternalContinuity(id);
        if (!cont) continue;

        bool isSelected = (strcmp(selectedContinuityId_, id.c_str()) == 0);
        if (ImGui::Selectable(id.c_str(), isSelected)) {
            strncpy(selectedContinuityId_, id.c_str(), sizeof(selectedContinuityId_) - 1);
        }

        if (isSelected) {
            ImGui::Indent();
            ImGui::Text("Eternity: %.3f", cont->eternity);
            ImGui::Text("Persistence: %.3f", cont->persistence);
            ImGui::Text("Endurance: %.3f", cont->endurance);
            ImGui::Text("Resilience: %.3f", cont->resilience);
            ImGui::Text("Permanence: %.3f", cont->permanence);
            ImGui::Text("Immortality: %.3f", cont->immortality);
            ImGui::Text("Timelessness: %.3f", cont->timelessness);
            ImGui::Text("Indestructibility: %.3f", cont->indestructibility);
            ImGui::Text("Perpetuity: %.3f", cont->perpetuity);
            ImGui::Text("Sustainability: %.3f", cont->sustainability);
            ImGui::Unindent();
        }
    }
    ImGui::EndChild();

    // History plots
    if (!continuities.empty()) {
        auto first = engine_.ReadEternalContinuity(continuities[0]);
        if (first) {
            eternityHistory_.push_back((float)first->eternity);
            persistenceHistory_.push_back((float)first->persistence);
            enduranceHistory_.push_back((float)first->endurance);
            resilienceHistory_.push_back((float)first->resilience);
            permanenceHistory_.push_back((float)first->permanence);
            immortalityHistory_.push_back((float)first->immortality);
            timelessnessHistory_.push_back((float)first->timelessness);
            indestructibilityHistory_.push_back((float)first->indestructibility);
            perpetuityHistory_.push_back((float)first->perpetuity);
            sustainabilityHistory_.push_back((float)first->sustainability);

            if (eternityHistory_.size() > MAX_HISTORY) eternityHistory_.erase(eternityHistory_.begin());
            if (persistenceHistory_.size() > MAX_HISTORY) persistenceHistory_.erase(persistenceHistory_.begin());
            if (enduranceHistory_.size() > MAX_HISTORY) enduranceHistory_.erase(enduranceHistory_.begin());
            if (resilienceHistory_.size() > MAX_HISTORY) resilienceHistory_.erase(resilienceHistory_.begin());
            if (permanenceHistory_.size() > MAX_HISTORY) permanenceHistory_.erase(permanenceHistory_.begin());
            if (immortalityHistory_.size() > MAX_HISTORY) immortalityHistory_.erase(immortalityHistory_.begin());
            if (timelessnessHistory_.size() > MAX_HISTORY) timelessnessHistory_.erase(timelessnessHistory_.begin());
            if (indestructibilityHistory_.size() > MAX_HISTORY) indestructibilityHistory_.erase(indestructibilityHistory_.begin());
            if (perpetuityHistory_.size() > MAX_HISTORY) perpetuityHistory_.erase(perpetuityHistory_.begin());
            if (sustainabilityHistory_.size() > MAX_HISTORY) sustainabilityHistory_.erase(sustainabilityHistory_.begin());

            ImGui::PlotLines("Eternity", eternityHistory_.data(), (int)eternityHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 60));
            ImGui::PlotLines("Persistence", persistenceHistory_.data(), (int)persistenceHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 60));
            ImGui::PlotLines("Endurance", enduranceHistory_.data(), (int)enduranceHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 60));
            ImGui::PlotLines("Resilience", resilienceHistory_.data(), (int)resilienceHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 60));
            ImGui::PlotLines("Permanence", permanenceHistory_.data(), (int)permanenceHistory_.size(), 0, nullptr, 0.0f, 1.0f, ImVec2(0, 60));
        }
    }
}

void EternalContinuityPanel::RenderNodeEditor() {
    ImGui::Text("Continuity Node Editor");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    auto nodes = engine_.ListContinuityNodes(selectedContinuityId_);

    ImGui::Text("Nodes for: %s", selectedContinuityId_);

    if (ImGui::Button("Create Node")) {
        engine_.CreateContinuityNode(selectedContinuityId_);
    }

    ImGui::BeginChild("NodeList", ImVec2(0, 300), true);
    for (const auto& nodeId : nodes) {
        auto node = engine_.ReadContinuityNode(nodeId);
        if (!node) continue;

        ImGui::Text("Node: %s", nodeId.c_str());
        ImGui::Indent();
        ImGui::SliderFloat("Local Eternity", (float*)&node->localEternity, 0.0f, 1.0f);
        ImGui::SliderFloat("Global Eternity", (float*)&node->globalEternity, 0.0f, 1.0f);
        ImGui::SliderFloat("Persistence Level", (float*)&node->persistenceLevel, 0.0f, 1.0f);
        ImGui::SliderFloat("Endurance Index", (float*)&node->enduranceIndex, 0.0f, 1.0f);
        ImGui::SliderFloat("Resilience Factor", (float*)&node->resilienceFactor, 0.0f, 1.0f);
        ImGui::SliderFloat("Permanence Level", (float*)&node->permanenceLevel, 0.0f, 1.0f);
        if (ImGui::Button("Delete")) {
            engine_.DeleteContinuityNode(nodeId);
        }
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void EternalContinuityPanel::RenderStreamVisualizer() {
    ImGui::Text("Continuity Stream Visualizer");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    auto streams = engine_.ListContinuityStreams(selectedContinuityId_);

    if (ImGui::Button("Create Stream")) {
        engine_.CreateContinuityStream(selectedContinuityId_);
    }

    ImGui::BeginChild("StreamList", ImVec2(0, 400), true);
    for (const auto& streamId : streams) {
        auto stream = engine_.ReadContinuityStream(streamId);
        if (!stream) continue;

        ImGui::Text("Stream: %s", streamId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)stream->streamFlow, ImVec2(-1, 0), "Flow");
        ImGui::ProgressBar((float)stream->streamVelocity, ImVec2(-1, 0), "Velocity");
        ImGui::ProgressBar((float)stream->streamDensity, ImVec2(-1, 0), "Density");
        ImGui::ProgressBar((float)stream->streamPersistence, ImVec2(-1, 0), "Persistence");
        ImGui::ProgressBar((float)stream->streamResilience, ImVec2(-1, 0), "Resilience");
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void EternalContinuityPanel::RenderWaveAnalyzer() {
    ImGui::Text("Continuity Wave Analyzer");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    auto waves = engine_.ListContinuityWaves(selectedContinuityId_);

    if (ImGui::Button("Create Wave")) {
        engine_.CreateContinuityWave(selectedContinuityId_);
    }

    ImGui::BeginChild("WaveList", ImVec2(0, 400), true);
    for (const auto& waveId : waves) {
        auto wave = engine_.ReadContinuityWave(waveId);
        if (!wave) continue;

        ImGui::Text("Wave: %s", waveId.c_str());
        ImGui::Indent();
        ImGui::SliderFloat("Frequency", (float*)&wave->frequency, 0.0f, 2.0f);
        ImGui::SliderFloat("Amplitude", (float*)&wave->amplitude, 0.0f, 1.0f);
        ImGui::SliderFloat("Phase", (float*)&wave->phase, 0.0f, 6.28f);
        ImGui::ProgressBar((float)wave->resonance, ImVec2(-1, 0), "Resonance");
        ImGui::ProgressBar((float)wave->persistence, ImVec2(-1, 0), "Persistence");
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void EternalContinuityPanel::RenderMatrixView() {
    ImGui::Text("Continuity Matrix (14x14)");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    auto matrices = engine_.ListContinuityMatrices(selectedContinuityId_);

    if (ImGui::Button("Create Matrix")) {
        engine_.CreateContinuityMatrix(selectedContinuityId_);
    }

    for (const auto& matrixId : matrices) {
        auto matrix = engine_.ReadContinuityMatrix(matrixId);
        if (!matrix) continue;

        ImGui::Text("Matrix: %s", matrixId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)matrix->coherence, ImVec2(-1, 0), "Coherence");
        ImGui::ProgressBar((float)matrix->stability, ImVec2(-1, 0), "Stability");
        ImGui::ProgressBar((float)matrix->persistence, ImVec2(-1, 0), "Persistence");

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

void EternalContinuityPanel::RenderTensorView() {
    ImGui::Text("Continuity Tensor (11x11x11)");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    auto tensors = engine_.ListContinuityTensors(selectedContinuityId_);

    if (ImGui::Button("Create Tensor")) {
        engine_.CreateContinuityTensor(selectedContinuityId_);
    }

    for (const auto& tensorId : tensors) {
        auto tensor = engine_.ReadContinuityTensor(tensorId);
        if (!tensor) continue;

        ImGui::Text("Tensor: %s", tensorId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)tensor->harmony, ImVec2(-1, 0), "Harmony");
        ImGui::ProgressBar((float)tensor->eternity, ImVec2(-1, 0), "Eternity");
        ImGui::ProgressBar((float)tensor->continuity, ImVec2(-1, 0), "Continuity");
        ImGui::Text("Dimensions: 11x11x11");
        ImGui::Unindent();
    }
}

void EternalContinuityPanel::RenderClarityMonitor() {
    ImGui::Text("Continuity Clarity Monitor");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    auto clarities = engine_.ListContinuityClarities(selectedContinuityId_);

    if (ImGui::Button("Create Clarity")) {
        engine_.CreateContinuityClarity(selectedContinuityId_);
    }

    ImGui::BeginChild("ClarityList", ImVec2(0, 400), true);
    for (const auto& clarityId : clarities) {
        auto clarity = engine_.ReadContinuityClarity(clarityId);
        if (!clarity) continue;

        ImGui::Text("Clarity: %s", clarityId.c_str());
        ImGui::Indent();
        ImGui::ProgressBar((float)clarity->clarity, ImVec2(-1, 0), "Clarity");
        ImGui::ProgressBar((float)clarity->purity, ImVec2(-1, 0), "Purity");
        ImGui::ProgressBar((float)clarity->coherence, ImVec2(-1, 0), "Coherence");
        ImGui::ProgressBar((float)clarity->resonance, ImVec2(-1, 0), "Resonance");
        ImGui::ProgressBar((float)clarity->persistence, ImVec2(-1, 0), "Persistence");
        ImGui::Unindent();
        ImGui::Separator();
    }
    ImGui::EndChild();
}

void EternalContinuityPanel::RenderPersistenceView() {
    ImGui::Text("Temporal Persistence (Batch 126)");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    if (ImGui::Button("Create Persistence Field")) {
        engine_.CreatePersistenceField(selectedContinuityId_);
    }

    ImGui::Text("Persistence fields maintain temporal anchors");
    ImGui::Text("that resist decay and ensure continuity");
    ImGui::Text("across time.");
}

void EternalContinuityPanel::RenderEnduranceView() {
    ImGui::Text("Endurance Matrix (Batch 127)");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    if (ImGui::Button("Create Endurance Matrix")) {
        engine_.CreateEnduranceMatrix(selectedContinuityId_);
    }

    ImGui::Text("Endurance matrices track stress, recovery,");
    ImGui::Text("and capacity across a 10x10 grid of cells.");
}

void EternalContinuityPanel::RenderResilienceView() {
    ImGui::Text("Resilience Web (Batch 128)");
    ImGui::Separator();

    if (strlen(selectedContinuityId_) == 0) {
        ImGui::Text("Select a continuity entity first");
        return;
    }

    if (ImGui::Button("Create Resilience Web")) {
        engine_.CreateResilienceWeb(selectedContinuityId_);
    }

    ImGui::Text("Resilience webs provide fault tolerance");
    ImGui::Text("and self-healing through interconnected");
    ImGui::Text("nodes with redundancy and adaptability.");
}

void EternalContinuityPanel::ProcessHotkeys() {
    // Ctrl+Shift+F126 to toggle
    if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) &&
        ImGui::IsKeyDown(ImGuiKey_LeftShift) &&
        ImGui::IsKeyPressed(ImGuiKey_F12, false)) {
        ToggleVisible();
    }
}

} // namespace EternalContinuity
