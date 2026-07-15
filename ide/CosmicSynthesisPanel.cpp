#include "CosmicSynthesisPanel.hpp"
#include "CosmicSynthesisEngine.hpp"
#include "CosmicSynthesisLoop.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>

namespace CosmicSynthesis {

// Static member definitions
bool CosmicSynthesisPanel::s_initialized = false;
bool CosmicSynthesisPanel::s_visible = true;
CosmicSynthesisPanelTab CosmicSynthesisPanel::s_activeTab = CosmicSynthesisPanelTab::CosmicStructure;
int CosmicSynthesisPanel::s_dockingLocation = 1; // Right side by default

std::string CosmicSynthesisPanel::s_selectedCosmicId;
std::string CosmicSynthesisPanel::s_selectedSynthesisId;
std::string CosmicSynthesisPanel::s_selectedHarmonyId;
std::string CosmicSynthesisPanel::s_selectedBalanceId;
std::string CosmicSynthesisPanel::s_selectedUnityId;

CosmicSynthesisPanel::StructureSelectedCallback CosmicSynthesisPanel::s_structureCallback;
CosmicSynthesisPanel::SynthesisSelectedCallback CosmicSynthesisPanel::s_synthesisCallback;
CosmicSynthesisPanel::HarmonySelectedCallback CosmicSynthesisPanel::s_harmonyCallback;
CosmicSynthesisPanel::BalanceSelectedCallback CosmicSynthesisPanel::s_balanceCallback;
CosmicSynthesisPanel::UnitySelectedCallback CosmicSynthesisPanel::s_unityCallback;

nlohmann::json CosmicSynthesisPanel::s_cachedMetrics;
std::vector<nlohmann::json> CosmicSynthesisPanel::s_cachedStructures;
std::vector<nlohmann::json> CosmicSynthesisPanel::s_cachedSynthesisCosmics;
std::vector<nlohmann::json> CosmicSynthesisPanel::s_cachedHarmonyCosmics;
std::vector<nlohmann::json> CosmicSynthesisPanel::s_cachedBalanceCosmics;
std::vector<nlohmann::json> CosmicSynthesisPanel::s_cachedUnityCosmics;
std::chrono::steady_clock::time_point CosmicSynthesisPanel::s_lastRefresh;

char CosmicSynthesisPanel::s_newStructureName[256] = {};
char CosmicSynthesisPanel::s_newSynthesisName[256] = {};
char CosmicSynthesisPanel::s_newHarmonyName[256] = {};
char CosmicSynthesisPanel::s_newBalanceName[256] = {};
char CosmicSynthesisPanel::s_newUnityName[256] = {};

void CosmicSynthesisPanel::Init() {
    if (s_initialized) return;
    
    // Register with loop for automatic refresh
    CosmicSynthesisLoop::RegisterUpdateCallback([](float) {
        auto now = std::chrono::steady_clock::now();
        if (now - s_lastRefresh > std::chrono::seconds(1)) {
            RefreshData();
            s_lastRefresh = now;
        }
    });
    
    s_initialized = true;
    RefreshData();
}

void CosmicSynthesisPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

bool CosmicSynthesisPanel::IsInitialized() {
    return s_initialized;
}

void CosmicSynthesisPanel::Render() {
    if (!s_visible) return;
    
    bool open = s_visible;
    Render(&open);
    s_visible = open;
}

void CosmicSynthesisPanel::Render(bool* p_open) {
    if (!p_open || !*p_open) return;
    
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Cosmic Synthesis Panel##CosmicSynthesis", p_open)) {
        // Tab bar
        if (ImGui::BeginTabBar("CosmicSynthesisTabs")) {
            if (ImGui::BeginTabItem("Cosmic Structure")) {
                s_activeTab = CosmicSynthesisPanelTab::CosmicStructure;
                RenderCosmicStructureTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Synthesis Cosmic")) {
                s_activeTab = CosmicSynthesisPanelTab::SynthesisCosmic;
                RenderSynthesisCosmicTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Harmony Cosmic")) {
                s_activeTab = CosmicSynthesisPanelTab::HarmonyCosmic;
                RenderHarmonyCosmicTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Balance Cosmic")) {
                s_activeTab = CosmicSynthesisPanelTab::BalanceCosmic;
                RenderBalanceCosmicTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Unity Cosmic")) {
                s_activeTab = CosmicSynthesisPanelTab::UnityCosmic;
                RenderUnityCosmicTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Metrics")) {
                s_activeTab = CosmicSynthesisPanelTab::Metrics;
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Visualization")) {
                s_activeTab = CosmicSynthesisPanelTab::Visualization;
                RenderVisualizationTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void CosmicSynthesisPanel::Show() {
    s_visible = true;
}

void CosmicSynthesisPanel::Hide() {
    s_visible = false;
}

void CosmicSynthesisPanel::ToggleVisibility() {
    s_visible = !s_visible;
}

bool CosmicSynthesisPanel::IsVisible() {
    return s_visible;
}

void CosmicSynthesisPanel::SetActiveTab(CosmicSynthesisPanelTab tab) {
    s_activeTab = tab;
}

CosmicSynthesisPanelTab CosmicSynthesisPanel::GetActiveTab() {
    return s_activeTab;
}

void CosmicSynthesisPanel::SetStructureSelectedCallback(const StructureSelectedCallback& callback) {
    s_structureCallback = callback;
}

void CosmicSynthesisPanel::SetSynthesisSelectedCallback(const SynthesisSelectedCallback& callback) {
    s_synthesisCallback = callback;
}

void CosmicSynthesisPanel::SetHarmonySelectedCallback(const HarmonySelectedCallback& callback) {
    s_harmonyCallback = callback;
}

void CosmicSynthesisPanel::SetBalanceSelectedCallback(const BalanceSelectedCallback& callback) {
    s_balanceCallback = callback;
}

void CosmicSynthesisPanel::SetUnitySelectedCallback(const UnitySelectedCallback& callback) {
    s_unityCallback = callback;
}

void CosmicSynthesisPanel::RefreshData() {
    RefreshStructures();
    RefreshSynthesisCosmics();
    RefreshHarmonyCosmics();
    RefreshBalanceCosmics();
    RefreshUnityCosmics();
    s_cachedMetrics = CosmicSynthesisEngine::GetCosmicSynthesisMetrics();
}

void CosmicSynthesisPanel::RefreshStructures() {
    s_cachedStructures.clear();
    auto structures = CosmicSynthesisEngine::GetAllCosmicSynthesisStructures();
    for (auto& s : structures) {
        s_cachedStructures.push_back(s.ToJson());
    }
}

void CosmicSynthesisPanel::RefreshSynthesisCosmics() {
    s_cachedSynthesisCosmics.clear();
    auto synthesisList = CosmicSynthesisEngine::GetAllSynthesisCosmics();
    for (auto& s : synthesisList) {
        s_cachedSynthesisCosmics.push_back(s.ToJson());
    }
}

void CosmicSynthesisPanel::RefreshHarmonyCosmics() {
    s_cachedHarmonyCosmics.clear();
    auto harmonyList = CosmicSynthesisEngine::GetAllHarmonyCosmics();
    for (auto& h : harmonyList) {
        s_cachedHarmonyCosmics.push_back(h.ToJson());
    }
}

void CosmicSynthesisPanel::RefreshBalanceCosmics() {
    s_cachedBalanceCosmics.clear();
    auto balanceList = CosmicSynthesisEngine::GetAllBalanceCosmics();
    for (auto& b : balanceList) {
        s_cachedBalanceCosmics.push_back(b.ToJson());
    }
}

void CosmicSynthesisPanel::RefreshUnityCosmics() {
    s_cachedUnityCosmics.clear();
    auto unityList = CosmicSynthesisEngine::GetAllUnityCosmics();
    for (auto& u : unityList) {
        s_cachedUnityCosmics.push_back(u.ToJson());
    }
}

nlohmann::json CosmicSynthesisPanel::GetCurrentMetrics() {
    return s_cachedMetrics;
}

std::vector<nlohmann::json> CosmicSynthesisPanel::GetCurrentStructures() {
    return s_cachedStructures;
}

std::vector<nlohmann::json> CosmicSynthesisPanel::GetCurrentSynthesisCosmics() {
    return s_cachedSynthesisCosmics;
}

std::vector<nlohmann::json> CosmicSynthesisPanel::GetCurrentHarmonyCosmics() {
    return s_cachedHarmonyCosmics;
}

std::vector<nlohmann::json> CosmicSynthesisPanel::GetCurrentBalanceCosmics() {
    return s_cachedBalanceCosmics;
}

std::vector<nlohmann::json> CosmicSynthesisPanel::GetCurrentUnityCosmics() {
    return s_cachedUnityCosmics;
}

void CosmicSynthesisPanel::RegisterHotkey() {
    // Hotkey registration would be handled by IDE framework
    // Ctrl+Shift+F105 for Cosmic Synthesis Panel
}

void CosmicSynthesisPanel::UnregisterHotkey() {
    // Unregister hotkey
}

void CosmicSynthesisPanel::HandleHotkey() {
    ToggleVisibility();
}

void CosmicSynthesisPanel::SetDockingLocation(int location) {
    s_dockingLocation = location;
}

int CosmicSynthesisPanel::GetDockingLocation() {
    return s_dockingLocation;
}

// Tab renderers
void CosmicSynthesisPanel::RenderCosmicStructureTab() {
    ImGui::Columns(2, "CosmicStructureColumns");
    
    // Left column - List
    ImGui::Text("Cosmic Structures");
    ImGui::Separator();
    
    ImGui::InputText("New Structure Name", s_newStructureName, sizeof(s_newStructureName));
    if (ImGui::Button("Create Structure")) {
        if (strlen(s_newStructureName) > 0) {
            CosmicSynthesisEngine::CreateCosmicSynthesisStructure(s_newStructureName);
            memset(s_newStructureName, 0, sizeof(s_newStructureName));
            RefreshStructures();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedStructures) {
        std::string cosmicId = s.value("cosmicId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedCosmicId == cosmicId);
        
        if (ImGui::Selectable((name + "##" + cosmicId).c_str(), isSelected)) {
            s_selectedCosmicId = cosmicId;
            if (s_structureCallback) s_structureCallback(cosmicId);
        }
    }
    
    ImGui::NextColumn();
    
    // Right column - Details
    if (!s_selectedCosmicId.empty()) {
        RenderStructureDetails(s_selectedCosmicId);
    } else {
        ImGui::Text("Select a structure to view details");
    }
    
    ImGui::Columns(1);
}

void CosmicSynthesisPanel::RenderStructureDetails(const std::string& cosmicId) {
    auto structure = CosmicSynthesisEngine::GetCosmicSynthesisStructure(cosmicId);
    if (!structure) return;
    
    ImGui::Text("Structure: %s", structure->name.c_str());
    ImGui::Text("ID: %s", structure->cosmicId.c_str());
    ImGui::Separator();
    
    // Metrics
    ImGui::Text("Cosmicness: %.2f", structure->cosmicness);
    ImGui::ProgressBar(structure->cosmicness, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Expand Cosmicness")) {
        CosmicSynthesisEngine::ExpandCosmicness(cosmicId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Synthesis: %.2f", structure->synthesis);
    ImGui::ProgressBar(structure->synthesis, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Catalyze Synthesis")) {
        CosmicSynthesisEngine::CatalyzeSynthesis(cosmicId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Harmony: %.2f", structure->harmony);
    ImGui::ProgressBar(structure->harmony, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Attune Harmony")) {
        CosmicSynthesisEngine::AttuneHarmony(cosmicId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Balance: %.2f", structure->balance);
    ImGui::ProgressBar(structure->balance, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Establish Balance")) {
        CosmicSynthesisEngine::EstablishBalance(cosmicId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Unity: %.2f", structure->unity);
    ImGui::ProgressBar(structure->unity, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Forge Unity")) {
        CosmicSynthesisEngine::ForgeUnity(cosmicId, 0.1f);
    }
    
    if (ImGui::Button("Delete Structure", ImVec2(120, 0))) {
        CosmicSynthesisEngine::DestroyCosmicSynthesisStructure(cosmicId);
        s_selectedCosmicId.clear();
        RefreshStructures();
    }
}

void CosmicSynthesisPanel::RenderSynthesisCosmicTab() {
    ImGui::Columns(2, "SynthesisCosmicColumns");
    
    ImGui::Text("Synthesis Cosmics");
    ImGui::Separator();
    
    ImGui::InputText("New Synthesis Name", s_newSynthesisName, sizeof(s_newSynthesisName));
    if (ImGui::Button("Create Synthesis")) {
        if (strlen(s_newSynthesisName) > 0) {
            CosmicSynthesisEngine::CreateSynthesisCosmic(s_newSynthesisName);
            memset(s_newSynthesisName, 0, sizeof(s_newSynthesisName));
            RefreshSynthesisCosmics();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedSynthesisCosmics) {
        std::string synthesisId = s.value("synthesisId", "");
        std::string name = s.value("name", "");
        bool isSynthesized = s.value("isSynthesized", false);
        bool isSelected = (s_selectedSynthesisId == synthesisId);
        
        std::string label = name + (isSynthesized ? " [Synthesized]" : "");
        if (ImGui::Selectable((label + "##" + synthesisId).c_str(), isSelected)) {
            s_selectedSynthesisId = synthesisId;
            if (s_synthesisCallback) s_synthesisCallback(synthesisId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedSynthesisId.empty()) {
        RenderSynthesisDetails(s_selectedSynthesisId);
    } else {
        ImGui::Text("Select a synthesis to view details");
    }
    
    ImGui::Columns(1);
}

void CosmicSynthesisPanel::RenderSynthesisDetails(const std::string& synthesisId) {
    auto synthesis = CosmicSynthesisEngine::GetSynthesisCosmic(synthesisId);
    if (!synthesis) return;
    
    ImGui::Text("Synthesis: %s", synthesis->name.c_str());
    ImGui::Text("ID: %s", synthesis->synthesisId.c_str());
    ImGui::Text("Status: %s", synthesis->isSynthesized ? "Synthesized" : "Forming");
    ImGui::Separator();
    
    ImGui::Text("Synthesis: %.2f", synthesis->synthesis);
    ImGui::ProgressBar(synthesis->synthesis, ImVec2(-1, 0), "");
    
    ImGui::Text("Integration: %.2f", synthesis->integration);
    ImGui::ProgressBar(synthesis->integration, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Deepen Integration")) {
        CosmicSynthesisEngine::DeepenIntegration(synthesisId, 0.1f);
    }
    
    ImGui::Text("Fusion: %.2f", synthesis->fusion);
    ImGui::ProgressBar(synthesis->fusion, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Catalyze Fusion")) {
        CosmicSynthesisEngine::CatalyzeFusion(synthesisId, 0.1f);
    }
    
    if (!synthesis->isSynthesized && ImGui::Button("Declare Synthesized")) {
        CosmicSynthesisEngine::DeclareSynthesized(synthesisId);
        RefreshSynthesisCosmics();
    }
    
    if (ImGui::Button("Delete Synthesis", ImVec2(120, 0))) {
        CosmicSynthesisEngine::DestroySynthesisCosmic(synthesisId);
        s_selectedSynthesisId.clear();
        RefreshSynthesisCosmics();
    }
}

void CosmicSynthesisPanel::RenderHarmonyCosmicTab() {
    ImGui::Columns(2, "HarmonyCosmicColumns");
    
    ImGui::Text("Harmony Cosmics");
    ImGui::Separator();
    
    ImGui::InputText("New Harmony Name", s_newHarmonyName, sizeof(s_newHarmonyName));
    if (ImGui::Button("Create Harmony")) {
        if (strlen(s_newHarmonyName) > 0) {
            CosmicSynthesisEngine::CreateHarmonyCosmic(s_newHarmonyName);
            memset(s_newHarmonyName, 0, sizeof(s_newHarmonyName));
            RefreshHarmonyCosmics();
        }
    }
    
    ImGui::Separator();
    
    for (auto& h : s_cachedHarmonyCosmics) {
        std::string harmonyId = h.value("harmonyId", "");
        std::string name = h.value("name", "");
        bool isSelected = (s_selectedHarmonyId == harmonyId);
        
        if (ImGui::Selectable((name + "##" + harmonyId).c_str(), isSelected)) {
            s_selectedHarmonyId = harmonyId;
            if (s_harmonyCallback) s_harmonyCallback(harmonyId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedHarmonyId.empty()) {
        RenderHarmonyDetails(s_selectedHarmonyId);
    } else {
        ImGui::Text("Select a harmony to view details");
    }
    
    ImGui::Columns(1);
}

void CosmicSynthesisPanel::RenderHarmonyDetails(const std::string& harmonyId) {
    auto harmony = CosmicSynthesisEngine::GetHarmonyCosmic(harmonyId);
    if (!harmony) return;
    
    ImGui::Text("Harmony: %s", harmony->name.c_str());
    ImGui::Text("ID: %s", harmony->harmonyId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Harmony: %.2f", harmony->harmony);
    ImGui::ProgressBar(harmony->harmony, ImVec2(-1, 0), "");
    
    ImGui::Text("Resonance: %.2f", harmony->resonance);
    ImGui::ProgressBar(harmony->resonance, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Amplify Resonance")) {
        CosmicSynthesisEngine::AmplifyResonance(harmonyId, 0.1f);
    }
    
    ImGui::Text("Alignment: %.2f", harmony->alignment);
    ImGui::ProgressBar(harmony->alignment, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Perfect Alignment")) {
        CosmicSynthesisEngine::PerfectAlignment(harmonyId, 0.1f);
    }
    
    if (ImGui::Button("Delete Harmony", ImVec2(120, 0))) {
        CosmicSynthesisEngine::DestroyHarmonyCosmic(harmonyId);
        s_selectedHarmonyId.clear();
        RefreshHarmonyCosmics();
    }
}

void CosmicSynthesisPanel::RenderBalanceCosmicTab() {
    ImGui::Columns(2, "BalanceCosmicColumns");
    
    ImGui::Text("Balance Cosmics");
    ImGui::Separator();
    
    ImGui::InputText("New Balance Name", s_newBalanceName, sizeof(s_newBalanceName));
    if (ImGui::Button("Create Balance")) {
        if (strlen(s_newBalanceName) > 0) {
            CosmicSynthesisEngine::CreateBalanceCosmic(s_newBalanceName);
            memset(s_newBalanceName, 0, sizeof(s_newBalanceName));
            RefreshBalanceCosmics();
        }
    }
    
    ImGui::Separator();
    
    for (auto& b : s_cachedBalanceCosmics) {
        std::string balanceId = b.value("balanceId", "");
        std::string name = b.value("name", "");
        bool isBalanced = b.value("isBalanced", false);
        bool isSelected = (s_selectedBalanceId == balanceId);
        
        std::string label = name + (isBalanced ? " [Balanced]" : "");
        if (ImGui::Selectable((label + "##" + balanceId).c_str(), isSelected)) {
            s_selectedBalanceId = balanceId;
            if (s_balanceCallback) s_balanceCallback(balanceId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedBalanceId.empty()) {
        RenderBalanceDetails(s_selectedBalanceId);
    } else {
        ImGui::Text("Select a balance to view details");
    }
    
    ImGui::Columns(1);
}

void CosmicSynthesisPanel::RenderBalanceDetails(const std::string& balanceId) {
    auto balance = CosmicSynthesisEngine::GetBalanceCosmic(balanceId);
    if (!balance) return;
    
    ImGui::Text("Balance: %s", balance->name.c_str());
    ImGui::Text("ID: %s", balance->balanceId.c_str());
    ImGui::Text("Status: %s", balance->isBalanced ? "Balanced" : "Unstable");
    ImGui::Separator();
    
    ImGui::Text("Balance: %.2f", balance->balance);
    ImGui::ProgressBar(balance->balance, ImVec2(-1, 0), "");
    
    ImGui::Text("Equilibrium: %.2f", balance->equilibrium);
    ImGui::ProgressBar(balance->equilibrium, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Restore Equilibrium")) {
        CosmicSynthesisEngine::RestoreEquilibrium(balanceId, 0.1f);
    }
    
    ImGui::Text("Stability: %.2f", balance->stability);
    ImGui::ProgressBar(balance->stability, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Ensure Stability")) {
        CosmicSynthesisEngine::EnsureStability(balanceId, 0.1f);
    }
    
    if (!balance->isBalanced && ImGui::Button("Declare Balanced")) {
        CosmicSynthesisEngine::DeclareBalanced(balanceId);
        RefreshBalanceCosmics();
    }
    
    if (ImGui::Button("Delete Balance", ImVec2(120, 0))) {
        CosmicSynthesisEngine::DestroyBalanceCosmic(balanceId);
        s_selectedBalanceId.clear();
        RefreshBalanceCosmics();
    }
}

void CosmicSynthesisPanel::RenderUnityCosmicTab() {
    ImGui::Columns(2, "UnityCosmicColumns");
    
    ImGui::Text("Unity Cosmics");
    ImGui::Separator();
    
    ImGui::InputText("New Unity Name", s_newUnityName, sizeof(s_newUnityName));
    if (ImGui::Button("Create Unity")) {
        if (strlen(s_newUnityName) > 0) {
            CosmicSynthesisEngine::CreateUnityCosmic(s_newUnityName);
            memset(s_newUnityName, 0, sizeof(s_newUnityName));
            RefreshUnityCosmics();
        }
    }
    
    ImGui::Separator();
    
    for (auto& u : s_cachedUnityCosmics) {
        std::string unityId = u.value("unityId", "");
        std::string name = u.value("name", "");
        bool isSelected = (s_selectedUnityId == unityId);
        
        if (ImGui::Selectable((name + "##" + unityId).c_str(), isSelected)) {
            s_selectedUnityId = unityId;
            if (s_unityCallback) s_unityCallback(unityId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedUnityId.empty()) {
        RenderUnityDetails(s_selectedUnityId);
    } else {
        ImGui::Text("Select a unity to view details");
    }
    
    ImGui::Columns(1);
}

void CosmicSynthesisPanel::RenderUnityDetails(const std::string& unityId) {
    auto unity = CosmicSynthesisEngine::GetUnityCosmic(unityId);
    if (!unity) return;
    
    ImGui::Text("Unity: %s", unity->name.c_str());
    ImGui::Text("ID: %s", unity->unityId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Unity: %.2f", unity->unity);
    ImGui::ProgressBar(unity->unity, ImVec2(-1, 0), "");
    
    ImGui::Text("Cohesion: %.2f", unity->cohesion);
    ImGui::ProgressBar(unity->cohesion, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Strengthen Cohesion")) {
        CosmicSynthesisEngine::StrengthenCohesion(unityId, 0.1f);
    }
    
    ImGui::Text("Oneness: %.2f", unity->oneness);
    ImGui::ProgressBar(unity->oneness, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Realize Oneness")) {
        CosmicSynthesisEngine::RealizeOneness(unityId, 0.1f);
    }
    
    if (ImGui::Button("Delete Unity", ImVec2(120, 0))) {
        CosmicSynthesisEngine::DestroyUnityCosmic(unityId);
        s_selectedUnityId.clear();
        RefreshUnityCosmics();
    }
}

void CosmicSynthesisPanel::RenderMetricsTab() {
    RenderMetricsDashboard();
}

void CosmicSynthesisPanel::RenderMetricsDashboard() {
    ImGui::Text("Cosmic Synthesis Metrics");
    ImGui::Separator();
    
    if (s_cachedMetrics.empty()) {
        ImGui::Text("No metrics available");
        return;
    }
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Cosmic Structures: %d", s_cachedMetrics.value("cosmicStructureCount", 0));
    ImGui::Text("Synthesis Cosmics: %d", s_cachedMetrics.value("synthesisCosmicCount", 0));
    ImGui::Text("Harmony Cosmics: %d", s_cachedMetrics.value("harmonyCosmicCount", 0));
    ImGui::Text("Balance Cosmics: %d", s_cachedMetrics.value("balanceCosmicCount", 0));
    ImGui::Text("Unity Cosmics: %d", s_cachedMetrics.value("unityCosmicCount", 0));
    
    ImGui::NextColumn();
    
    float totalCosmicness = s_cachedMetrics.value("totalCosmicness", 0.0f);
    float totalSynthesis = s_cachedMetrics.value("totalSynthesis", 0.0f);
    float totalHarmony = s_cachedMetrics.value("totalHarmony", 0.0f);
    float totalBalance = s_cachedMetrics.value("totalBalance", 0.0f);
    float totalUnity = s_cachedMetrics.value("totalUnity", 0.0f);
    
    ImGui::Text("Total Cosmicness: %.2f", totalCosmicness);
    ImGui::Text("Total Synthesis: %.2f", totalSynthesis);
    ImGui::Text("Total Harmony: %.2f", totalHarmony);
    ImGui::Text("Total Balance: %.2f", totalBalance);
    ImGui::Text("Total Unity: %.2f", totalUnity);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    
    int synthesizedCount = s_cachedMetrics.value("synthesizedCount", 0);
    int balancedCount = s_cachedMetrics.value("balancedCount", 0);
    
    ImGui::Text("Synthesized: %d", synthesizedCount);
    ImGui::Text("Balanced: %d", balancedCount);
    
    // Loop metrics
    ImGui::Separator();
    ImGui::Text("Loop Metrics");
    ImGui::Text("TPS: %.1f", CosmicSynthesisLoop::GetCurrentTPS());
    ImGui::Text("Tick Count: %lld", CosmicSynthesisLoop::GetTickCount());
}

void CosmicSynthesisPanel::RenderVisualizationTab() {
    RenderCosmicVisualization();
}

void CosmicSynthesisPanel::RenderCosmicVisualization() {
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    // Background - cosmic gradient
    draw_list->AddRectFilled(canvas_pos, 
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(15, 10, 30, 255));
    
    float center_x = canvas_pos.x + canvas_size.x * 0.5f;
    float center_y = canvas_pos.y + canvas_size.y * 0.5f;
    
    // Draw cosmic structures as synthesis orbs
    int idx = 0;
    for (auto& s : s_cachedStructures) {
        float cosmicness = s.value("cosmicness", 0.0f);
        float synthesis = s.value("synthesis", 0.0f);
        float harmony = s.value("harmony", 0.0f);
        float balance = s.value("balance", 0.0f);
        float unity = s.value("unity", 0.0f);
        
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)s_cachedStructures.size());
        float radius = 80.0f + (cosmicness * 60.0f);
        
        float x = center_x + std::cos(angle) * radius;
        float y = center_y + std::sin(angle) * radius;
        
        float orb_size = 12.0f + (synthesis * 18.0f);
        
        // Synthesis glow effect
        for (int i = 4; i >= 0; i--) {
            float glow_size = orb_size + i * 6;
            int alpha = 50 - i * 10;
            draw_list->AddCircleFilled(ImVec2(x, y), glow_size,
                IM_COL32(100 + (int)(harmony * 155), 200 + (int)(balance * 55), 255, alpha));
        }
        
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), orb_size,
            IM_COL32(150 + (int)(unity * 105), 220, 255, 255));
        
        // Synthesis ring
        if (synthesis > 0.3f) {
            float ring_radius = orb_size + 8.0f + synthesis * 10.0f;
            draw_list->AddCircle(ImVec2(x, y), ring_radius,
                IM_COL32(255, 200, 100, 150), 32, 2.0f);
        }
        
        idx++;
    }
    
    // Center cosmic core
    draw_list->AddCircleFilled(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(255, 255, 255, 220));
    draw_list->AddCircle(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(100, 200, 255, 255), 32, 4.0f);
    
    // Legend
    ImGui::SetCursorPosY(canvas_size.y - 60);
    ImGui::Text("Visualization: Cosmic Synthesis");
    ImGui::Text("Orbs: Cosmic Structures | Rings: Synthesis | Center: Cosmic Core");
}

} // namespace CosmicSynthesis
