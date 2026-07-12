#include "InfiniteWisdomPanel.hpp"
#include "InfiniteWisdomEngine.hpp"
#include "InfiniteWisdomLoop.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>

namespace InfiniteWisdom {

// Static member definitions
bool InfiniteWisdomPanel::s_initialized = false;
bool InfiniteWisdomPanel::s_visible = true;
InfiniteWisdomPanelTab InfiniteWisdomPanel::s_activeTab = InfiniteWisdomPanelTab::InfiniteStructure;
int InfiniteWisdomPanel::s_dockingLocation = 1;

std::string InfiniteWisdomPanel::s_selectedInfiniteId;
std::string InfiniteWisdomPanel::s_selectedWisdomId;
std::string InfiniteWisdomPanel::s_selectedKnowledgeId;
std::string InfiniteWisdomPanel::s_selectedInsightId;
std::string InfiniteWisdomPanel::s_selectedTruthId;
std::string InfiniteWisdomPanel::s_selectedEnlightenmentId;

InfiniteWisdomPanel::StructureSelectedCallback InfiniteWisdomPanel::s_structureCallback;
InfiniteWisdomPanel::WisdomSelectedCallback InfiniteWisdomPanel::s_wisdomCallback;
InfiniteWisdomPanel::KnowledgeSelectedCallback InfiniteWisdomPanel::s_knowledgeCallback;
InfiniteWisdomPanel::InsightSelectedCallback InfiniteWisdomPanel::s_insightCallback;
InfiniteWisdomPanel::TruthSelectedCallback InfiniteWisdomPanel::s_truthCallback;
InfiniteWisdomPanel::EnlightenmentSelectedCallback InfiniteWisdomPanel::s_enlightenmentCallback;

nlohmann::json InfiniteWisdomPanel::s_cachedMetrics;
std::vector<nlohmann::json> InfiniteWisdomPanel::s_cachedStructures;
std::vector<nlohmann::json> InfiniteWisdomPanel::s_cachedWisdomInfinites;
std::vector<nlohmann::json> InfiniteWisdomPanel::s_cachedKnowledgeInfinites;
std::vector<nlohmann::json> InfiniteWisdomPanel::s_cachedInsightInfinites;
std::vector<nlohmann::json> InfiniteWisdomPanel::s_cachedTruthInfinites;
std::vector<nlohmann::json> InfiniteWisdomPanel::s_cachedEnlightenmentInfinites;
std::chrono::steady_clock::time_point InfiniteWisdomPanel::s_lastRefresh;

char InfiniteWisdomPanel::s_newStructureName[256] = {};
char InfiniteWisdomPanel::s_newWisdomName[256] = {};
char InfiniteWisdomPanel::s_newKnowledgeName[256] = {};
char InfiniteWisdomPanel::s_newInsightName[256] = {};
char InfiniteWisdomPanel::s_newTruthName[256] = {};
char InfiniteWisdomPanel::s_newEnlightenmentName[256] = {};

void InfiniteWisdomPanel::Init() {
    if (s_initialized) return;
    
    InfiniteWisdomLoop::RegisterUpdateCallback([](float) {
        auto now = std::chrono::steady_clock::now();
        if (now - s_lastRefresh > std::chrono::seconds(1)) {
            RefreshData();
            s_lastRefresh = now;
        }
    });
    
    s_initialized = true;
    RefreshData();
}

void InfiniteWisdomPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

bool InfiniteWisdomPanel::IsInitialized() {
    return s_initialized;
}

void InfiniteWisdomPanel::Render() {
    if (!s_visible) return;
    bool open = s_visible;
    Render(&open);
    s_visible = open;
}

void InfiniteWisdomPanel::Render(bool* p_open) {
    if (!p_open || !*p_open) return;
    
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Infinite Wisdom Panel##InfiniteWisdom", p_open)) {
        if (ImGui::BeginTabBar("InfiniteWisdomTabs")) {
            if (ImGui::BeginTabItem("Infinite Structure")) {
                s_activeTab = InfiniteWisdomPanelTab::InfiniteStructure;
                RenderInfiniteStructureTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Wisdom Infinite")) {
                s_activeTab = InfiniteWisdomPanelTab::WisdomInfinite;
                RenderWisdomInfiniteTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Knowledge Infinite")) {
                s_activeTab = InfiniteWisdomPanelTab::KnowledgeInfinite;
                RenderKnowledgeInfiniteTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Insight Infinite")) {
                s_activeTab = InfiniteWisdomPanelTab::InsightInfinite;
                RenderInsightInfiniteTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Truth Infinite")) {
                s_activeTab = InfiniteWisdomPanelTab::TruthInfinite;
                RenderTruthInfiniteTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Enlightenment Infinite")) {
                s_activeTab = InfiniteWisdomPanelTab::EnlightenmentInfinite;
                RenderEnlightenmentInfiniteTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Metrics")) {
                s_activeTab = InfiniteWisdomPanelTab::Metrics;
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Visualization")) {
                s_activeTab = InfiniteWisdomPanelTab::Visualization;
                RenderVisualizationTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void InfiniteWisdomPanel::Show() { s_visible = true; }
void InfiniteWisdomPanel::Hide() { s_visible = false; }
void InfiniteWisdomPanel::ToggleVisibility() { s_visible = !s_visible; }
bool InfiniteWisdomPanel::IsVisible() { return s_visible; }

void InfiniteWisdomPanel::SetActiveTab(InfiniteWisdomPanelTab tab) { s_activeTab = tab; }
InfiniteWisdomPanelTab InfiniteWisdomPanel::GetActiveTab() { return s_activeTab; }

void InfiniteWisdomPanel::SetStructureSelectedCallback(const StructureSelectedCallback& callback) { s_structureCallback = callback; }
void InfiniteWisdomPanel::SetWisdomSelectedCallback(const WisdomSelectedCallback& callback) { s_wisdomCallback = callback; }
void InfiniteWisdomPanel::SetKnowledgeSelectedCallback(const KnowledgeSelectedCallback& callback) { s_knowledgeCallback = callback; }
void InfiniteWisdomPanel::SetInsightSelectedCallback(const InsightSelectedCallback& callback) { s_insightCallback = callback; }
void InfiniteWisdomPanel::SetTruthSelectedCallback(const TruthSelectedCallback& callback) { s_truthCallback = callback; }
void InfiniteWisdomPanel::SetEnlightenmentSelectedCallback(const EnlightenmentSelectedCallback& callback) { s_enlightenmentCallback = callback; }

void InfiniteWisdomPanel::RefreshData() {
    RefreshStructures();
    RefreshWisdomInfinites();
    RefreshKnowledgeInfinites();
    RefreshInsightInfinites();
    RefreshTruthInfinites();
    RefreshEnlightenmentInfinites();
    s_cachedMetrics = InfiniteWisdomEngine::GetInfiniteWisdomMetrics();
}

void InfiniteWisdomPanel::RefreshStructures() {
    s_cachedStructures.clear();
    auto structures = InfiniteWisdomEngine::GetAllInfiniteWisdomStructures();
    for (auto& s : structures) s_cachedStructures.push_back(s.ToJson());
}

void InfiniteWisdomPanel::RefreshWisdomInfinites() {
    s_cachedWisdomInfinites.clear();
    auto wisdomList = InfiniteWisdomEngine::GetAllWisdomInfinites();
    for (auto& w : wisdomList) s_cachedWisdomInfinites.push_back(w.ToJson());
}

void InfiniteWisdomPanel::RefreshKnowledgeInfinites() {
    s_cachedKnowledgeInfinites.clear();
    auto knowledgeList = InfiniteWisdomEngine::GetAllKnowledgeInfinites();
    for (auto& k : knowledgeList) s_cachedKnowledgeInfinites.push_back(k.ToJson());
}

void InfiniteWisdomPanel::RefreshInsightInfinites() {
    s_cachedInsightInfinites.clear();
    auto insightList = InfiniteWisdomEngine::GetAllInsightInfinites();
    for (auto& i : insightList) s_cachedInsightInfinites.push_back(i.ToJson());
}

void InfiniteWisdomPanel::RefreshTruthInfinites() {
    s_cachedTruthInfinites.clear();
    auto truthList = InfiniteWisdomEngine::GetAllTruthInfinites();
    for (auto& t : truthList) s_cachedTruthInfinites.push_back(t.ToJson());
}

void InfiniteWisdomPanel::RefreshEnlightenmentInfinites() {
    s_cachedEnlightenmentInfinites.clear();
    auto enlightenmentList = InfiniteWisdomEngine::GetAllEnlightenmentInfinites();
    for (auto& e : enlightenmentList) s_cachedEnlightenmentInfinites.push_back(e.ToJson());
}

nlohmann::json InfiniteWisdomPanel::GetCurrentMetrics() { return s_cachedMetrics; }
std::vector<nlohmann::json> InfiniteWisdomPanel::GetCurrentStructures() { return s_cachedStructures; }
std::vector<nlohmann::json> InfiniteWisdomPanel::GetCurrentWisdomInfinites() { return s_cachedWisdomInfinites; }
std::vector<nlohmann::json> InfiniteWisdomPanel::GetCurrentKnowledgeInfinites() { return s_cachedKnowledgeInfinites; }
std::vector<nlohmann::json> InfiniteWisdomPanel::GetCurrentInsightInfinites() { return s_cachedInsightInfinites; }
std::vector<nlohmann::json> InfiniteWisdomPanel::GetCurrentTruthInfinites() { return s_cachedTruthInfinites; }
std::vector<nlohmann::json> InfiniteWisdomPanel::GetCurrentEnlightenmentInfinites() { return s_cachedEnlightenmentInfinites; }

void InfiniteWisdomPanel::RegisterHotkey() {}
void InfiniteWisdomPanel::UnregisterHotkey() {}
void InfiniteWisdomPanel::HandleHotkey() { ToggleVisibility(); }
void InfiniteWisdomPanel::SetDockingLocation(int location) { s_dockingLocation = location; }
int InfiniteWisdomPanel::GetDockingLocation() { return s_dockingLocation; }

void InfiniteWisdomPanel::RenderInfiniteStructureTab() {
    ImGui::Columns(2, "InfiniteStructureColumns");
    
    ImGui::Text("Infinite Structures");
    ImGui::Separator();
    
    ImGui::InputText("New Structure Name", s_newStructureName, sizeof(s_newStructureName));
    if (ImGui::Button("Create Structure")) {
        if (strlen(s_newStructureName) > 0) {
            InfiniteWisdomEngine::CreateInfiniteWisdomStructure(s_newStructureName);
            memset(s_newStructureName, 0, sizeof(s_newStructureName));
            RefreshStructures();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedStructures) {
        std::string infiniteId = s.value("infiniteId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedInfiniteId == infiniteId);
        
        if (ImGui::Selectable((name + "##" + infiniteId).c_str(), isSelected)) {
            s_selectedInfiniteId = infiniteId;
            if (s_structureCallback) s_structureCallback(infiniteId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedInfiniteId.empty()) {
        RenderStructureDetails(s_selectedInfiniteId);
    } else {
        ImGui::Text("Select a structure to view details");
    }
    
    ImGui::Columns(1);
}

void InfiniteWisdomPanel::RenderStructureDetails(const std::string& infiniteId) {
    auto structure = InfiniteWisdomEngine::GetInfiniteWisdomStructure(infiniteId);
    if (!structure) return;
    
    ImGui::Text("Structure: %s", structure->name.c_str());
    ImGui::Text("ID: %s", structure->infiniteId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Infiniteness: %.2f", structure->infiniteness);
    ImGui::ProgressBar(structure->infiniteness, ImVec2(-1, 0), "");
    if (ImGui::Button("Expand Infiniteness")) InfiniteWisdomEngine::ExpandInfiniteness(infiniteId, 0.1f);
    
    ImGui::Text("Wisdom: %.2f", structure->wisdom);
    ImGui::ProgressBar(structure->wisdom, ImVec2(-1, 0), "");
    if (ImGui::Button("Deepen Wisdom")) InfiniteWisdomEngine::DeepenWisdom(infiniteId, 0.1f);
    
    ImGui::Text("Knowledge: %.2f", structure->knowledge);
    ImGui::ProgressBar(structure->knowledge, ImVec2(-1, 0), "");
    if (ImGui::Button("Accumulate Knowledge")) InfiniteWisdomEngine::AccumulateKnowledge(infiniteId, 0.1f);
    
    ImGui::Text("Insight: %.2f", structure->insight);
    ImGui::ProgressBar(structure->insight, ImVec2(-1, 0), "");
    if (ImGui::Button("Illuminate Insight")) InfiniteWisdomEngine::IlluminateInsight(infiniteId, 0.1f);
    
    ImGui::Text("Truth: %.2f", structure->truth);
    ImGui::ProgressBar(structure->truth, ImVec2(-1, 0), "");
    if (ImGui::Button("Reveal Truth")) InfiniteWisdomEngine::RevealTruth(infiniteId, 0.1f);
    
    ImGui::Text("Enlightenment: %.2f", structure->enlightenment);
    ImGui::ProgressBar(structure->enlightenment, ImVec2(-1, 0), "");
    if (ImGui::Button("Awaken Enlightenment")) InfiniteWisdomEngine::AwakenEnlightenment(infiniteId, 0.1f);
    
    if (ImGui::Button("Delete Structure", ImVec2(120, 0))) {
        InfiniteWisdomEngine::DestroyInfiniteWisdomStructure(infiniteId);
        s_selectedInfiniteId.clear();
        RefreshStructures();
    }
}

void InfiniteWisdomPanel::RenderWisdomInfiniteTab() {
    ImGui::Columns(2, "WisdomInfiniteColumns");
    
    ImGui::Text("Wisdom Infinites");
    ImGui::Separator();
    
    ImGui::InputText("New Wisdom Name", s_newWisdomName, sizeof(s_newWisdomName));
    if (ImGui::Button("Create Wisdom")) {
        if (strlen(s_newWisdomName) > 0) {
            InfiniteWisdomEngine::CreateWisdomInfinite(s_newWisdomName);
            memset(s_newWisdomName, 0, sizeof(s_newWisdomName));
            RefreshWisdomInfinites();
        }
    }
    
    ImGui::Separator();
    
    for (auto& w : s_cachedWisdomInfinites) {
        std::string wisdomId = w.value("wisdomId", "");
        std::string name = w.value("name", "");
        bool isWise = w.value("isWise", false);
        bool isSelected = (s_selectedWisdomId == wisdomId);
        
        std::string label = name + (isWise ? " [Wise]" : "");
        if (ImGui::Selectable((label + "##" + wisdomId).c_str(), isSelected)) {
            s_selectedWisdomId = wisdomId;
            if (s_wisdomCallback) s_wisdomCallback(wisdomId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedWisdomId.empty()) {
        RenderWisdomDetails(s_selectedWisdomId);
    } else {
        ImGui::Text("Select a wisdom to view details");
    }
    
    ImGui::Columns(1);
}

void InfiniteWisdomPanel::RenderWisdomDetails(const std::string& wisdomId) {
    auto wisdom = InfiniteWisdomEngine::GetWisdomInfinite(wisdomId);
    if (!wisdom) return;
    
    ImGui::Text("Wisdom: %s", wisdom->name.c_str());
    ImGui::Text("ID: %s", wisdom->wisdomId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Wisdom: %.2f", wisdom->wisdom);
    ImGui::ProgressBar(wisdom->wisdom, ImVec2(-1, 0), "");
    
    ImGui::Text("Understanding: %.2f", wisdom->understanding);
    ImGui::ProgressBar(wisdom->understanding, ImVec2(-1, 0), "");
    if (ImGui::Button("Gain Understanding")) InfiniteWisdomEngine::GainUnderstanding(wisdomId, 0.1f);
    
    ImGui::Text("Clarity: %.2f", wisdom->clarity);
    ImGui::ProgressBar(wisdom->clarity, ImVec2(-1, 0), "");
    if (ImGui::Button("Achieve Clarity")) InfiniteWisdomEngine::AchieveClarity(wisdomId, 0.1f);
    
    if (!wisdom->isWise && ImGui::Button("Declare Wise")) {
        InfiniteWisdomEngine::DeclareWise(wisdomId);
        RefreshWisdomInfinites();
    }
    
    if (ImGui::Button("Delete Wisdom", ImVec2(120, 0))) {
        InfiniteWisdomEngine::DestroyWisdomInfinite(wisdomId);
        s_selectedWisdomId.clear();
        RefreshWisdomInfinites();
    }
}

void InfiniteWisdomPanel::RenderKnowledgeInfiniteTab() {
    ImGui::Columns(2, "KnowledgeInfiniteColumns");
    
    ImGui::Text("Knowledge Infinites");
    ImGui::Separator();
    
    ImGui::InputText("New Knowledge Name", s_newKnowledgeName, sizeof(s_newKnowledgeName));
    if (ImGui::Button("Create Knowledge")) {
        if (strlen(s_newKnowledgeName) > 0) {
            InfiniteWisdomEngine::CreateKnowledgeInfinite(s_newKnowledgeName);
            memset(s_newKnowledgeName, 0, sizeof(s_newKnowledgeName));
            RefreshKnowledgeInfinites();
        }
    }
    
    ImGui::Separator();
    
    for (auto& k : s_cachedKnowledgeInfinites) {
        std::string knowledgeId = k.value("knowledgeId", "");
        std::string name = k.value("name", "");
        bool isKnown = k.value("isKnown", false);
        bool isSelected = (s_selectedKnowledgeId == knowledgeId);
        
        std::string label = name + (isKnown ? " [Known]" : "");
        if (ImGui::Selectable((label + "##" + knowledgeId).c_str(), isSelected)) {
            s_selectedKnowledgeId = knowledgeId;
            if (s_knowledgeCallback) s_knowledgeCallback(knowledgeId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedKnowledgeId.empty()) {
        RenderKnowledgeDetails(s_selectedKnowledgeId);
    } else {
        ImGui::Text("Select a knowledge to view details");
    }
    
    ImGui::Columns(1);
}

void InfiniteWisdomPanel::RenderKnowledgeDetails(const std::string& knowledgeId) {
    auto knowledge = InfiniteWisdomEngine::GetKnowledgeInfinite(knowledgeId);
    if (!knowledge) return;
    
    ImGui::Text("Knowledge: %s", knowledge->name.c_str());
    ImGui::Text("ID: %s", knowledge->knowledgeId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Knowledge: %.2f", knowledge->knowledge);
    ImGui::ProgressBar(knowledge->knowledge, ImVec2(-1, 0), "");
    
    ImGui::Text("Depth: %.2f", knowledge->depth);
    ImGui::ProgressBar(knowledge->depth, ImVec2(-1, 0), "");
    if (ImGui::Button("Deepen Knowledge")) InfiniteWisdomEngine::DeepenKnowledge(knowledgeId, 0.1f);
    
    ImGui::Text("Breadth: %.2f", knowledge->breadth);
    ImGui::ProgressBar(knowledge->breadth, ImVec2(-1, 0), "");
    if (ImGui::Button("Expand Breadth")) InfiniteWisdomEngine::ExpandBreadth(knowledgeId, 0.1f);
    
    if (!knowledge->isKnown && ImGui::Button("Declare Known")) {
        InfiniteWisdomEngine::DeclareKnown(knowledgeId);
        RefreshKnowledgeInfinites();
    }
    
    if (ImGui::Button("Delete Knowledge", ImVec2(120, 0))) {
        InfiniteWisdomEngine::DestroyKnowledgeInfinite(knowledgeId);
        s_selectedKnowledgeId.clear();
        RefreshKnowledgeInfinites();
    }
}

void InfiniteWisdomPanel::RenderInsightInfiniteTab() {
    ImGui::Columns(2, "InsightInfiniteColumns");
    
    ImGui::Text("Insight Infinites");
    ImGui::Separator();
    
    ImGui::InputText("New Insight Name", s_newInsightName, sizeof(s_newInsightName));
    if (ImGui::Button("Create Insight")) {
        if (strlen(s_newInsightName) > 0) {
            InfiniteWisdomEngine::CreateInsightInfinite(s_newInsightName);
            memset(s_newInsightName, 0, sizeof(s_newInsightName));
            RefreshInsightInfinites();
        }
    }
    
    ImGui::Separator();
    
    for (auto& i : s_cachedInsightInfinites) {
        std::string insightId = i.value("insightId", "");
        std::string name = i.value("name", "");
        bool isInsightful = i.value("isInsightful", false);
        bool isSelected = (s_selectedInsightId == insightId);
        
        std::string label = name + (isInsightful ? " [Insightful]" : "");
        if (ImGui::Selectable((label + "##" + insightId).c_str(), isSelected)) {
            s_selectedInsightId = insightId;
            if (s_insightCallback) s_insightCallback(insightId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedInsightId.empty()) {
        RenderInsightDetails(s_selectedInsightId);
    } else {
        ImGui::Text("Select an insight to view details");
    }
    
    ImGui::Columns(1);
}

void InfiniteWisdomPanel::RenderInsightDetails(const std::string& insightId) {
    auto insight = InfiniteWisdomEngine::GetInsightInfinite(insightId);
    if (!insight) return;
    
    ImGui::Text("Insight: %s", insight->name.c_str());
    ImGui::Text("ID: %s", insight->insightId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Insight: %.2f", insight->insight);
    ImGui::ProgressBar(insight->insight, ImVec2(-1, 0), "");
    
    ImGui::Text("Perception: %.2f", insight->perception);
    ImGui::ProgressBar(insight->perception, ImVec2(-1, 0), "");
    if (ImGui::Button("Sharpen Perception")) InfiniteWisdomEngine::SharpenPerception(insightId, 0.1f);
    
    ImGui::Text("Intuition: %.2f", insight->intuition);
    ImGui::ProgressBar(insight->intuition, ImVec2(-1, 0), "");
    if (ImGui::Button("Trust Intuition")) InfiniteWisdomEngine::TrustIntuition(insightId, 0.1f);
    
    if (!insight->isInsightful && ImGui::Button("Declare Insightful")) {
        InfiniteWisdomEngine::DeclareInsightful(insightId);
        RefreshInsightInfinites();
    }
    
    if (ImGui::Button("Delete Insight", ImVec2(120, 0))) {
        InfiniteWisdomEngine::DestroyInsightInfinite(insightId);
        s_selectedInsightId.clear();
        RefreshInsightInfinites();
    }
}

void InfiniteWisdomPanel::RenderTruthInfiniteTab() {
    ImGui::Columns(2, "TruthInfiniteColumns");
    
    ImGui::Text("Truth Infinites");
    ImGui::Separator();
    
    ImGui::InputText("New Truth Name", s_newTruthName, sizeof(s_newTruthName));
    if (ImGui::Button("Create Truth")) {
        if (strlen(s_newTruthName) > 0) {
            InfiniteWisdomEngine::CreateTruthInfinite(s_newTruthName);
            memset(s_newTruthName, 0, sizeof(s_newTruthName));
            RefreshTruthInfinites();
        }
    }
    
    ImGui::Separator();
    
    for (auto& t : s_cachedTruthInfinites) {
        std::string truthId = t.value("truthId", "");
        std::string name = t.value("name", "");
        bool isTrue = t.value("isTrue", false);
        bool isSelected = (s_selectedTruthId == truthId);
        
        std::string label = name + (isTrue ? " [True]" : "");
        if (ImGui::Selectable((label + "##" + truthId).c_str(), isSelected)) {
            s_selectedTruthId = truthId;
            if (s_truthCallback) s_truthCallback(truthId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedTruthId.empty()) {
        RenderTruthDetails(s_selectedTruthId);
    } else {
        ImGui::Text("Select a truth to view details");
    }
    
    ImGui::Columns(1);
}

void InfiniteWisdomPanel::RenderTruthDetails(const std::string& truthId) {
    auto truth = InfiniteWisdomEngine::GetTruthInfinite(truthId);
    if (!truth) return;
    
    ImGui::Text("Truth: %s", truth->name.c_str());
    ImGui::Text("ID: %s", truth->truthId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Truth: %.2f", truth->truth);
    ImGui::ProgressBar(truth->truth, ImVec2(-1, 0), "");
    
    ImGui::Text("Veracity: %.2f", truth->veracity);
    ImGui::ProgressBar(truth->veracity, ImVec2(-1, 0), "");
    if (ImGui::Button("Verify Veracity")) InfiniteWisdomEngine::VerifyVeracity(truthId, 0.1f);
    
    ImGui::Text("Authenticity: %.2f", truth->authenticity);
    ImGui::ProgressBar(truth->authenticity, ImVec2(-1, 0), "");
    if (ImGui::Button("Confirm Authenticity")) InfiniteWisdomEngine::ConfirmAuthenticity(truthId, 0.1f);
    
    if (!truth->isTrue && ImGui::Button("Declare True")) {
        InfiniteWisdomEngine::DeclareTrue(truthId);
        RefreshTruthInfinites();
    }
    
    if (ImGui::Button("Delete Truth", ImVec2(120, 0))) {
        InfiniteWisdomEngine::DestroyTruthInfinite(truthId);
        s_selectedTruthId.clear();
        RefreshTruthInfinites();
    }
}

void InfiniteWisdomPanel::RenderEnlightenmentInfiniteTab() {
    ImGui::Columns(2, "EnlightenmentInfiniteColumns");
    
    ImGui::Text("Enlightenment Infinites");
    ImGui::Separator();
    
    ImGui::InputText("New Enlightenment Name", s_newEnlightenmentName, sizeof(s_newEnlightenmentName));
    if (ImGui::Button("Create Enlightenment")) {
        if (strlen(s_newEnlightenmentName) > 0) {
            InfiniteWisdomEngine::CreateEnlightenmentInfinite(s_newEnlightenmentName);
            memset(s_newEnlightenmentName, 0, sizeof(s_newEnlightenmentName));
            RefreshEnlightenmentInfinites();
        }
    }
    
    ImGui::Separator();
    
    for (auto& e : s_cachedEnlightenmentInfinites) {
        std::string enlightenmentId = e.value("enlightenmentId", "");
        std::string name = e.value("name", "");
        bool isEnlightened = e.value("isEnlightened", false);
        bool isSelected = (s_selectedEnlightenmentId == enlightenmentId);
        
        std::string label = name + (isEnlightened ? " [Enlightened]" : "");
        if (ImGui::Selectable((label + "##" + enlightenmentId).c_str(), isSelected)) {
            s_selectedEnlightenmentId = enlightenmentId;
            if (s_enlightenmentCallback) s_enlightenmentCallback(enlightenmentId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedEnlightenmentId.empty()) {
        RenderEnlightenmentDetails(s_selectedEnlightenmentId);
    } else {
        ImGui::Text("Select an enlightenment to view details");
    }
    
    ImGui::Columns(1);
}

void InfiniteWisdomPanel::RenderEnlightenmentDetails(const std::string& enlightenmentId) {
    auto enlightenment = InfiniteWisdomEngine::GetEnlightenmentInfinite(enlightenmentId);
    if (!enlightenment) return;
    
    ImGui::Text("Enlightenment: %s", enlightenment->name.c_str());
    ImGui::Text("ID: %s", enlightenment->enlightenmentId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Enlightenment: %.2f", enlightenment->enlightenment);
    ImGui::ProgressBar(enlightenment->enlightenment, ImVec2(-1, 0), "");
    
    ImGui::Text("Awakening: %.2f", enlightenment->awakening);
    ImGui::ProgressBar(enlightenment->awakening, ImVec2(-1, 0), "");
    if (ImGui::Button("Deepen Awakening")) InfiniteWisdomEngine::DeepenAwakening(enlightenmentId, 0.1f);
    
    ImGui::Text("Realization: %.2f", enlightenment->realization);
    ImGui::ProgressBar(enlightenment->realization, ImVec2(-1, 0), "");
    if (ImGui::Button("Achieve Realization")) InfiniteWisdomEngine::AchieveRealization(enlightenmentId, 0.1f);
    
    if (!enlightenment->isEnlightened && ImGui::Button("Declare Enlightened")) {
        InfiniteWisdomEngine::DeclareEnlightened(enlightenmentId);
        RefreshEnlightenmentInfinites();
    }
    
    if (ImGui::Button("Delete Enlightenment", ImVec2(120, 0))) {
        InfiniteWisdomEngine::DestroyEnlightenmentInfinite(enlightenmentId);
        s_selectedEnlightenmentId.clear();
        RefreshEnlightenmentInfinites();
    }
}

void InfiniteWisdomPanel::RenderMetricsTab() {
    RenderMetricsDashboard();
}

void InfiniteWisdomPanel::RenderMetricsDashboard() {
    ImGui::Text("Infinite Wisdom Metrics");
    ImGui::Separator();
    
    if (s_cachedMetrics.empty()) {
        ImGui::Text("No metrics available");
        return;
    }
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Infinite Structures: %d", s_cachedMetrics.value("infiniteStructureCount", 0));
    ImGui::Text("Wisdom Infinites: %d", s_cachedMetrics.value("wisdomInfiniteCount", 0));
    ImGui::Text("Knowledge Infinites: %d", s_cachedMetrics.value("knowledgeInfiniteCount", 0));
    ImGui::Text("Insight Infinites: %d", s_cachedMetrics.value("insightInfiniteCount", 0));
    ImGui::Text("Truth Infinites: %d", s_cachedMetrics.value("truthInfiniteCount", 0));
    ImGui::Text("Enlightenment Infinites: %d", s_cachedMetrics.value("enlightenmentInfiniteCount", 0));
    
    ImGui::NextColumn();
    
    float totalInfiniteness = s_cachedMetrics.value("totalInfiniteness", 0.0f);
    float totalWisdom = s_cachedMetrics.value("totalWisdom", 0.0f);
    float totalKnowledge = s_cachedMetrics.value("totalKnowledge", 0.0f);
    float totalInsight = s_cachedMetrics.value("totalInsight", 0.0f);
    float totalTruth = s_cachedMetrics.value("totalTruth", 0.0f);
    float totalEnlightenment = s_cachedMetrics.value("totalEnlightenment", 0.0f);
    
    ImGui::Text("Total Infiniteness: %.2f", totalInfiniteness);
    ImGui::Text("Total Wisdom: %.2f", totalWisdom);
    ImGui::Text("Total Knowledge: %.2f", totalKnowledge);
    ImGui::Text("Total Insight: %.2f", totalInsight);
    ImGui::Text("Total Truth: %.2f", totalTruth);
    ImGui::Text("Total Enlightenment: %.2f", totalEnlightenment);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    
    int enlightenedCount = s_cachedMetrics.value("enlightenedCount", 0);
    ImGui::Text("Enlightened: %d", enlightenedCount);
    
    ImGui::Separator();
    ImGui::Text("Loop Metrics");
    ImGui::Text("TPS: %.1f", InfiniteWisdomLoop::GetCurrentTPS());
    ImGui::Text("Tick Count: %lld", InfiniteWisdomLoop::GetTickCount());
}

void InfiniteWisdomPanel::RenderVisualizationTab() {
    RenderInfiniteVisualization();
}

void InfiniteWisdomPanel::RenderInfiniteVisualization() {
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    // Background - infinite gradient
    draw_list->AddRectFilled(canvas_pos, 
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(20, 15, 40, 255));
    
    float center_x = canvas_pos.x + canvas_size.x * 0.5f;
    float center_y = canvas_pos.y + canvas_size.y * 0.5f;
    
    // Draw infinite structures as wisdom orbs
    int idx = 0;
    for (auto& s : s_cachedStructures) {
        float infiniteness = s.value("infiniteness", 0.0f);
        float wisdom = s.value("wisdom", 0.0f);
        float knowledge = s.value("knowledge", 0.0f);
        float insight = s.value("insight", 0.0f);
        float truth = s.value("truth", 0.0f);
        float enlightenment = s.value("enlightenment", 0.0f);
        
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)s_cachedStructures.size());
        float radius = 80.0f + (infiniteness * 60.0f);
        
        float x = center_x + std::cos(angle) * radius;
        float y = center_y + std::sin(angle) * radius;
        
        float orb_size = 12.0f + (wisdom * 18.0f);
        
        // Wisdom glow effect
        for (int i = 4; i >= 0; i--) {
            float glow_size = orb_size + i * 6;
            int alpha = 50 - i * 10;
            draw_list->AddCircleFilled(ImVec2(x, y), glow_size,
                IM_COL32(200 + (int)(knowledge * 55), 150 + (int)(insight * 105), 255, alpha));
        }
        
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), orb_size,
            IM_COL32(220, 200, 255, 255));
        
        // Truth ring
        if (truth > 0.3f) {
            float ring_radius = orb_size + 8.0f + truth * 10.0f;
            draw_list->AddCircle(ImVec2(x, y), ring_radius,
                IM_COL32(255, 255, 200, 150), 32, 2.0f);
        }
        
        // Enlightenment aura
        if (enlightenment > 0.5f) {
            float aura_radius = orb_size + 20.0f + enlightenment * 15.0f;
            draw_list->AddCircle(ImVec2(x, y), aura_radius,
                IM_COL32(255, 220, 100, 100), 32, 3.0f);
        }
        
        idx++;
    }
    
    // Center infinite core
    draw_list->AddCircleFilled(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(255, 255, 255, 220));
    draw_list->AddCircle(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(200, 180, 255, 255), 32, 4.0f);
    
    // Legend
    ImGui::SetCursorPosY(canvas_size.y - 60);
    ImGui::Text("Visualization: Infinite Wisdom");
    ImGui::Text("Orbs: Infinite Structures | Rings: Truth | Center: Infinite Core");
}

} // namespace InfiniteWisdom
