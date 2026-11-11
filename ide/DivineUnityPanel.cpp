#include "DivineUnityPanel.hpp"
#include "DivineUnityEngine.hpp"
#include "DivineUnityLoop.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>

namespace DivineUnity {

// Static member definitions
bool DivineUnityPanel::s_initialized = false;
bool DivineUnityPanel::s_visible = true;
DivineUnityPanelTab DivineUnityPanel::s_activeTab = DivineUnityPanelTab::DivineStructure;
int DivineUnityPanel::s_dockingLocation = 1; // Right side by default

std::string DivineUnityPanel::s_selectedDivineId;
std::string DivineUnityPanel::s_selectedUnityId;
std::string DivineUnityPanel::s_selectedGraceId;
std::string DivineUnityPanel::s_selectedLightId;
std::string DivineUnityPanel::s_selectedTruthId;

DivineUnityPanel::StructureSelectedCallback DivineUnityPanel::s_structureCallback;
DivineUnityPanel::UnitySelectedCallback DivineUnityPanel::s_unityCallback;
DivineUnityPanel::GraceSelectedCallback DivineUnityPanel::s_graceCallback;
DivineUnityPanel::LightSelectedCallback DivineUnityPanel::s_lightCallback;
DivineUnityPanel::TruthSelectedCallback DivineUnityPanel::s_truthCallback;

nlohmann::json DivineUnityPanel::s_cachedMetrics;
std::vector<nlohmann::json> DivineUnityPanel::s_cachedStructures;
std::vector<nlohmann::json> DivineUnityPanel::s_cachedUnityDivines;
std::vector<nlohmann::json> DivineUnityPanel::s_cachedGraceDivines;
std::vector<nlohmann::json> DivineUnityPanel::s_cachedLightDivines;
std::vector<nlohmann::json> DivineUnityPanel::s_cachedTruthDivines;
std::chrono::steady_clock::time_point DivineUnityPanel::s_lastRefresh;

char DivineUnityPanel::s_newStructureName[256] = {};
char DivineUnityPanel::s_newUnityName[256] = {};
char DivineUnityPanel::s_newGraceName[256] = {};
char DivineUnityPanel::s_newLightName[256] = {};
char DivineUnityPanel::s_newTruthName[256] = {};

void DivineUnityPanel::Init() {
    if (s_initialized) return;
    
    // Register with loop for automatic refresh
    DivineUnityLoop::RegisterUpdateCallback([](float) {
        auto now = std::chrono::steady_clock::now();
        if (now - s_lastRefresh > std::chrono::seconds(1)) {
            RefreshData();
            s_lastRefresh = now;
        }
    });
    
    s_initialized = true;
    RefreshData();
}

void DivineUnityPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

bool DivineUnityPanel::IsInitialized() {
    return s_initialized;
}

void DivineUnityPanel::Render() {
    if (!s_visible) return;
    
    bool open = s_visible;
    Render(&open);
    s_visible = open;
}

void DivineUnityPanel::Render(bool* p_open) {
    if (!p_open || !*p_open) return;
    
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Divine Unity Panel##DivineUnity", p_open)) {
        // Tab bar
        if (ImGui::BeginTabBar("DivineUnityTabs")) {
            if (ImGui::BeginTabItem("Divine Structure")) {
                s_activeTab = DivineUnityPanelTab::DivineStructure;
                RenderDivineStructureTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Unity Divine")) {
                s_activeTab = DivineUnityPanelTab::UnityDivine;
                RenderUnityDivineTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Grace Divine")) {
                s_activeTab = DivineUnityPanelTab::GraceDivine;
                RenderGraceDivineTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Light Divine")) {
                s_activeTab = DivineUnityPanelTab::LightDivine;
                RenderLightDivineTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Truth Divine")) {
                s_activeTab = DivineUnityPanelTab::TruthDivine;
                RenderTruthDivineTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Metrics")) {
                s_activeTab = DivineUnityPanelTab::Metrics;
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Visualization")) {
                s_activeTab = DivineUnityPanelTab::Visualization;
                RenderVisualizationTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void DivineUnityPanel::Show() {
    s_visible = true;
}

void DivineUnityPanel::Hide() {
    s_visible = false;
}

void DivineUnityPanel::ToggleVisibility() {
    s_visible = !s_visible;
}

bool DivineUnityPanel::IsVisible() {
    return s_visible;
}

void DivineUnityPanel::SetActiveTab(DivineUnityPanelTab tab) {
    s_activeTab = tab;
}

DivineUnityPanelTab DivineUnityPanel::GetActiveTab() {
    return s_activeTab;
}

void DivineUnityPanel::SetStructureSelectedCallback(const StructureSelectedCallback& callback) {
    s_structureCallback = callback;
}

void DivineUnityPanel::SetUnitySelectedCallback(const UnitySelectedCallback& callback) {
    s_unityCallback = callback;
}

void DivineUnityPanel::SetGraceSelectedCallback(const GraceSelectedCallback& callback) {
    s_graceCallback = callback;
}

void DivineUnityPanel::SetLightSelectedCallback(const LightSelectedCallback& callback) {
    s_lightCallback = callback;
}

void DivineUnityPanel::SetTruthSelectedCallback(const TruthSelectedCallback& callback) {
    s_truthCallback = callback;
}

void DivineUnityPanel::RefreshData() {
    RefreshStructures();
    RefreshUnityDivines();
    RefreshGraceDivines();
    RefreshLightDivines();
    RefreshTruthDivines();
    s_cachedMetrics = DivineUnityEngine::GetDivineUnityMetrics();
}

void DivineUnityPanel::RefreshStructures() {
    s_cachedStructures.clear();
    auto structures = DivineUnityEngine::GetAllDivineUnityStructures();
    for (auto& s : structures) {
        s_cachedStructures.push_back(s.ToJson());
    }
}

void DivineUnityPanel::RefreshUnityDivines() {
    s_cachedUnityDivines.clear();
    auto unities = DivineUnityEngine::GetAllUnityDivines();
    for (auto& u : unities) {
        s_cachedUnityDivines.push_back(u.ToJson());
    }
}

void DivineUnityPanel::RefreshGraceDivines() {
    s_cachedGraceDivines.clear();
    auto graces = DivineUnityEngine::GetAllGraceDivines();
    for (auto& g : graces) {
        s_cachedGraceDivines.push_back(g.ToJson());
    }
}

void DivineUnityPanel::RefreshLightDivines() {
    s_cachedLightDivines.clear();
    auto lights = DivineUnityEngine::GetAllLightDivines();
    for (auto& l : lights) {
        s_cachedLightDivines.push_back(l.ToJson());
    }
}

void DivineUnityPanel::RefreshTruthDivines() {
    s_cachedTruthDivines.clear();
    auto truths = DivineUnityEngine::GetAllTruthDivines();
    for (auto& t : truths) {
        s_cachedTruthDivines.push_back(t.ToJson());
    }
}

nlohmann::json DivineUnityPanel::GetCurrentMetrics() {
    return s_cachedMetrics;
}

std::vector<nlohmann::json> DivineUnityPanel::GetCurrentStructures() {
    return s_cachedStructures;
}

std::vector<nlohmann::json> DivineUnityPanel::GetCurrentUnityDivines() {
    return s_cachedUnityDivines;
}

std::vector<nlohmann::json> DivineUnityPanel::GetCurrentGraceDivines() {
    return s_cachedGraceDivines;
}

std::vector<nlohmann::json> DivineUnityPanel::GetCurrentLightDivines() {
    return s_cachedLightDivines;
}

std::vector<nlohmann::json> DivineUnityPanel::GetCurrentTruthDivines() {
    return s_cachedTruthDivines;
}

void DivineUnityPanel::RegisterHotkey() {
    // Hotkey registration would be handled by IDE framework
    // Ctrl+Shift+F101 for Divine Unity Panel
}

void DivineUnityPanel::UnregisterHotkey() {
    // Unregister hotkey
}

void DivineUnityPanel::HandleHotkey() {
    ToggleVisibility();
}

void DivineUnityPanel::SetDockingLocation(int location) {
    s_dockingLocation = location;
}

int DivineUnityPanel::GetDockingLocation() {
    return s_dockingLocation;
}

// Tab renderers
void DivineUnityPanel::RenderDivineStructureTab() {
    ImGui::Columns(2, "DivineStructureColumns");
    
    // Left column - List
    ImGui::Text("Divine Structures");
    ImGui::Separator();
    
    ImGui::InputText("New Structure Name", s_newStructureName, sizeof(s_newStructureName));
    if (ImGui::Button("Create Structure")) {
        if (strlen(s_newStructureName) > 0) {
            DivineUnityEngine::CreateDivineUnityStructure(s_newStructureName);
            memset(s_newStructureName, 0, sizeof(s_newStructureName));
            RefreshStructures();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedStructures) {
        std::string divineId = s.value("divineId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedDivineId == divineId);
        
        if (ImGui::Selectable((name + "##" + divineId).c_str(), isSelected)) {
            s_selectedDivineId = divineId;
            if (s_structureCallback) s_structureCallback(divineId);
        }
    }
    
    ImGui::NextColumn();
    
    // Right column - Details
    if (!s_selectedDivineId.empty()) {
        RenderStructureDetails(s_selectedDivineId);
    } else {
        ImGui::Text("Select a structure to view details");
    }
    
    ImGui::Columns(1);
}

void DivineUnityPanel::RenderStructureDetails(const std::string& divineId) {
    auto structure = DivineUnityEngine::GetDivineUnityStructure(divineId);
    if (!structure) return;
    
    ImGui::Text("Structure: %s", structure->name.c_str());
    ImGui::Text("ID: %s", structure->divineId.c_str());
    ImGui::Separator();
    
    // Metrics
    ImGui::Text("Divinity: %.2f", structure->divinity);
    ImGui::ProgressBar(structure->divinity, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Elevate Divinity")) {
        DivineUnityEngine::ElevateDivinity(divineId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Unity: %.2f", structure->unity);
    ImGui::ProgressBar(structure->unity, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Expand Unity")) {
        DivineUnityEngine::ExpandUnity(divineId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Grace: %.2f", structure->grace);
    ImGui::ProgressBar(structure->grace, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Bestow Grace")) {
        DivineUnityEngine::BestowGrace(divineId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Light: %.2f", structure->light);
    ImGui::ProgressBar(structure->light, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Shine Light")) {
        DivineUnityEngine::ShineLight(divineId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Truth: %.2f", structure->truth);
    ImGui::ProgressBar(structure->truth, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Reveal Truth")) {
        DivineUnityEngine::RevealTruth(divineId, 0.1f);
    }
    
    if (ImGui::Button("Delete Structure", ImVec2(120, 0))) {
        DivineUnityEngine::DestroyDivineUnityStructure(divineId);
        s_selectedDivineId.clear();
        RefreshStructures();
    }
}

void DivineUnityPanel::RenderUnityDivineTab() {
    ImGui::Columns(2, "UnityDivineColumns");
    
    ImGui::Text("Unity Divines");
    ImGui::Separator();
    
    ImGui::InputText("New Unity Name", s_newUnityName, sizeof(s_newUnityName));
    if (ImGui::Button("Create Unity")) {
        if (strlen(s_newUnityName) > 0) {
            DivineUnityEngine::CreateUnityDivine(s_newUnityName);
            memset(s_newUnityName, 0, sizeof(s_newUnityName));
            RefreshUnityDivines();
        }
    }
    
    ImGui::Separator();
    
    for (auto& u : s_cachedUnityDivines) {
        std::string unityId = u.value("unityId", "");
        std::string name = u.value("name", "");
        bool isUnified = u.value("isUnified", false);
        bool isSelected = (s_selectedUnityId == unityId);
        
        std::string label = name + (isUnified ? " [Unified]" : "");
        if (ImGui::Selectable((label + "##" + unityId).c_str(), isSelected)) {
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

void DivineUnityPanel::RenderUnityDetails(const std::string& unityId) {
    auto unity = DivineUnityEngine::GetUnityDivine(unityId);
    if (!unity) return;
    
    ImGui::Text("Unity: %s", unity->name.c_str());
    ImGui::Text("ID: %s", unity->unityId.c_str());
    ImGui::Text("Status: %s", unity->isUnified ? "Unified" : "Divided");
    ImGui::Separator();
    
    ImGui::Text("Unity: %.2f", unity->unity);
    ImGui::ProgressBar(unity->unity, ImVec2(-1, 0), "");
    
    ImGui::Text("Cohesion: %.2f", unity->cohesion);
    ImGui::ProgressBar(unity->cohesion, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Strengthen Cohesion")) {
        DivineUnityEngine::StrengthenCohesion(unityId, 0.1f);
    }
    
    ImGui::Text("Harmony: %.2f", unity->harmony);
    ImGui::ProgressBar(unity->harmony, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Cultivate Harmony")) {
        DivineUnityEngine::CultivateHarmony(unityId, 0.1f);
    }
    
    if (!unity->isUnified && ImGui::Button("Declare Unified")) {
        DivineUnityEngine::DeclareUnified(unityId);
        RefreshUnityDivines();
    }
    
    if (ImGui::Button("Delete Unity", ImVec2(120, 0))) {
        DivineUnityEngine::DestroyUnityDivine(unityId);
        s_selectedUnityId.clear();
        RefreshUnityDivines();
    }
}

void DivineUnityPanel::RenderGraceDivineTab() {
    ImGui::Columns(2, "GraceDivineColumns");
    
    ImGui::Text("Grace Divines");
    ImGui::Separator();
    
    ImGui::InputText("New Grace Name", s_newGraceName, sizeof(s_newGraceName));
    if (ImGui::Button("Create Grace")) {
        if (strlen(s_newGraceName) > 0) {
            DivineUnityEngine::CreateGraceDivine(s_newGraceName);
            memset(s_newGraceName, 0, sizeof(s_newGraceName));
            RefreshGraceDivines();
        }
    }
    
    ImGui::Separator();
    
    for (auto& g : s_cachedGraceDivines) {
        std::string graceId = g.value("graceId", "");
        std::string name = g.value("name", "");
        bool isSelected = (s_selectedGraceId == graceId);
        
        if (ImGui::Selectable((name + "##" + graceId).c_str(), isSelected)) {
            s_selectedGraceId = graceId;
            if (s_graceCallback) s_graceCallback(graceId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedGraceId.empty()) {
        RenderGraceDetails(s_selectedGraceId);
    } else {
        ImGui::Text("Select a grace to view details");
    }
    
    ImGui::Columns(1);
}

void DivineUnityPanel::RenderGraceDetails(const std::string& graceId) {
    auto grace = DivineUnityEngine::GetGraceDivine(graceId);
    if (!grace) return;
    
    ImGui::Text("Grace: %s", grace->name.c_str());
    ImGui::Text("ID: %s", grace->graceId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Grace: %.2f", grace->grace);
    ImGui::ProgressBar(grace->grace, ImVec2(-1, 0), "");
    
    ImGui::Text("Mercy: %.2f", grace->mercy);
    ImGui::ProgressBar(grace->mercy, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Extend Mercy")) {
        DivineUnityEngine::ExtendMercy(graceId, 0.1f);
    }
    
    ImGui::Text("Blessing: %.2f", grace->blessing);
    ImGui::ProgressBar(grace->blessing, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Grant Blessing")) {
        DivineUnityEngine::GrantBlessing(graceId, 0.1f);
    }
    
    if (ImGui::Button("Delete Grace", ImVec2(120, 0))) {
        DivineUnityEngine::DestroyGraceDivine(graceId);
        s_selectedGraceId.clear();
        RefreshGraceDivines();
    }
}

void DivineUnityPanel::RenderLightDivineTab() {
    ImGui::Columns(2, "LightDivineColumns");
    
    ImGui::Text("Light Divines");
    ImGui::Separator();
    
    ImGui::InputText("New Light Name", s_newLightName, sizeof(s_newLightName));
    if (ImGui::Button("Create Light")) {
        if (strlen(s_newLightName) > 0) {
            DivineUnityEngine::CreateLightDivine(s_newLightName);
            memset(s_newLightName, 0, sizeof(s_newLightName));
            RefreshLightDivines();
        }
    }
    
    ImGui::Separator();
    
    for (auto& l : s_cachedLightDivines) {
        std::string lightId = l.value("lightId", "");
        std::string name = l.value("name", "");
        bool isIlluminated = l.value("isIlluminated", false);
        bool isSelected = (s_selectedLightId == lightId);
        
        std::string label = name + (isIlluminated ? " [Illuminated]" : "");
        if (ImGui::Selectable((label + "##" + lightId).c_str(), isSelected)) {
            s_selectedLightId = lightId;
            if (s_lightCallback) s_lightCallback(lightId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedLightId.empty()) {
        RenderLightDetails(s_selectedLightId);
    } else {
        ImGui::Text("Select a light to view details");
    }
    
    ImGui::Columns(1);
}

void DivineUnityPanel::RenderLightDetails(const std::string& lightId) {
    auto light = DivineUnityEngine::GetLightDivine(lightId);
    if (!light) return;
    
    ImGui::Text("Light: %s", light->name.c_str());
    ImGui::Text("ID: %s", light->lightId.c_str());
    ImGui::Text("Status: %s", light->isIlluminated ? "Illuminated" : "Dim");
    ImGui::Separator();
    
    ImGui::Text("Light: %.2f", light->light);
    ImGui::ProgressBar(light->light, ImVec2(-1, 0), "");
    
    ImGui::Text("Radiance: %.2f", light->radiance);
    ImGui::ProgressBar(light->radiance, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Amplify Radiance")) {
        DivineUnityEngine::AmplifyRadiance(lightId, 0.1f);
    }
    
    ImGui::Text("Illumination: %.2f", light->illumination);
    ImGui::ProgressBar(light->illumination, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Expand Illumination")) {
        DivineUnityEngine::ExpandIllumination(lightId, 0.1f);
    }
    
    if (!light->isIlluminated && ImGui::Button("Declare Illuminated")) {
        DivineUnityEngine::DeclareIlluminated(lightId);
        RefreshLightDivines();
    }
    
    if (ImGui::Button("Delete Light", ImVec2(120, 0))) {
        DivineUnityEngine::DestroyLightDivine(lightId);
        s_selectedLightId.clear();
        RefreshLightDivines();
    }
}

void DivineUnityPanel::RenderTruthDivineTab() {
    ImGui::Columns(2, "TruthDivineColumns");
    
    ImGui::Text("Truth Divines");
    ImGui::Separator();
    
    ImGui::InputText("New Truth Name", s_newTruthName, sizeof(s_newTruthName));
    if (ImGui::Button("Create Truth")) {
        if (strlen(s_newTruthName) > 0) {
            DivineUnityEngine::CreateTruthDivine(s_newTruthName);
            memset(s_newTruthName, 0, sizeof(s_newTruthName));
            RefreshTruthDivines();
        }
    }
    
    ImGui::Separator();
    
    for (auto& t : s_cachedTruthDivines) {
        std::string truthId = t.value("truthId", "");
        std::string name = t.value("name", "");
        bool isSelected = (s_selectedTruthId == truthId);
        
        if (ImGui::Selectable((name + "##" + truthId).c_str(), isSelected)) {
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

void DivineUnityPanel::RenderTruthDetails(const std::string& truthId) {
    auto truth = DivineUnityEngine::GetTruthDivine(truthId);
    if (!truth) return;
    
    ImGui::Text("Truth: %s", truth->name.c_str());
    ImGui::Text("ID: %s", truth->truthId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Truth: %.2f", truth->truth);
    ImGui::ProgressBar(truth->truth, ImVec2(-1, 0), "");
    
    ImGui::Text("Veracity: %.2f", truth->veracity);
    ImGui::ProgressBar(truth->veracity, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Enhance Veracity")) {
        DivineUnityEngine::EnhanceVeracity(truthId, 0.1f);
    }
    
    ImGui::Text("Wisdom: %.2f", truth->wisdom);
    ImGui::ProgressBar(truth->wisdom, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Impart Wisdom")) {
        DivineUnityEngine::ImpartWisdom(truthId, 0.1f);
    }
    
    if (ImGui::Button("Delete Truth", ImVec2(120, 0))) {
        DivineUnityEngine::DestroyTruthDivine(truthId);
        s_selectedTruthId.clear();
        RefreshTruthDivines();
    }
}

void DivineUnityPanel::RenderMetricsTab() {
    RenderMetricsDashboard();
}

void DivineUnityPanel::RenderMetricsDashboard() {
    ImGui::Text("Divine Unity Metrics");
    ImGui::Separator();
    
    if (s_cachedMetrics.empty()) {
        ImGui::Text("No metrics available");
        return;
    }
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Divine Structures: %d", s_cachedMetrics.value("divineStructureCount", 0));
    ImGui::Text("Unity Divines: %d", s_cachedMetrics.value("unityDivineCount", 0));
    ImGui::Text("Grace Divines: %d", s_cachedMetrics.value("graceDivineCount", 0));
    ImGui::Text("Light Divines: %d", s_cachedMetrics.value("lightDivineCount", 0));
    ImGui::Text("Truth Divines: %d", s_cachedMetrics.value("truthDivineCount", 0));
    
    ImGui::NextColumn();
    
    float totalDivinity = s_cachedMetrics.value("totalDivinity", 0.0f);
    float totalUnity = s_cachedMetrics.value("totalUnity", 0.0f);
    float totalGrace = s_cachedMetrics.value("totalGrace", 0.0f);
    float totalLight = s_cachedMetrics.value("totalLight", 0.0f);
    float totalTruth = s_cachedMetrics.value("totalTruth", 0.0f);
    
    ImGui::Text("Total Divinity: %.2f", totalDivinity);
    ImGui::Text("Total Unity: %.2f", totalUnity);
    ImGui::Text("Total Grace: %.2f", totalGrace);
    ImGui::Text("Total Light: %.2f", totalLight);
    ImGui::Text("Total Truth: %.2f", totalTruth);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    
    int unifiedCount = s_cachedMetrics.value("unifiedCount", 0);
    int illuminatedCount = s_cachedMetrics.value("illuminatedCount", 0);
    
    ImGui::Text("Unified: %d", unifiedCount);
    ImGui::Text("Illuminated: %d", illuminatedCount);
    
    // Loop metrics
    ImGui::Separator();
    ImGui::Text("Loop Metrics");
    ImGui::Text("TPS: %.1f", DivineUnityLoop::GetCurrentTPS());
    ImGui::Text("Tick Count: %lld", DivineUnityLoop::GetTickCount());
}

void DivineUnityPanel::RenderVisualizationTab() {
    RenderDivineVisualization();
}

void DivineUnityPanel::RenderDivineVisualization() {
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    // Background
    draw_list->AddRectFilled(canvas_pos, 
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(20, 20, 30, 255));
    
    float center_x = canvas_pos.x + canvas_size.x * 0.5f;
    float center_y = canvas_pos.y + canvas_size.y * 0.5f;
    
    // Draw divine structures as luminous orbs
    int idx = 0;
    for (auto& s : s_cachedStructures) {
        float divinity = s.value("divinity", 0.0f);
        float unity = s.value("unity", 0.0f);
        float grace = s.value("grace", 0.0f);
        float light = s.value("light", 0.0f);
        float truth = s.value("truth", 0.0f);
        
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)s_cachedStructures.size());
        float radius = 100.0f + (divinity * 50.0f);
        
        float x = center_x + std::cos(angle) * radius;
        float y = center_y + std::sin(angle) * radius;
        
        float orb_size = 15.0f + (light * 20.0f);
        
        // Glow effect
        for (int i = 3; i >= 0; i--) {
            float glow_size = orb_size + i * 5;
            int alpha = 50 - i * 10;
            draw_list->AddCircleFilled(ImVec2(x, y), glow_size,
                IM_COL32(255, 215, 100 + (int)(grace * 100), alpha));
        }
        
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), orb_size,
            IM_COL32(255, 255, 200 + (int)(truth * 55), 255));
        
        // Unity rays
        if (unity > 0.5f) {
            float ray_length = 30.0f + unity * 40.0f;
            float end_x = center_x + std::cos(angle) * (radius - ray_length);
            float end_y = center_y + std::sin(angle) * (radius - ray_length);
            
            draw_list->AddLine(ImVec2(end_x, end_y), ImVec2(x, y),
                IM_COL32(200, 200, 255, 100 + (int)(unity * 100)), 2.0f);
        }
        
        idx++;
    }
    
    // Center divine core
    draw_list->AddCircleFilled(ImVec2(center_x, center_y), 25.0f,
        IM_COL32(255, 255, 255, 200));
    draw_list->AddCircle(ImVec2(center_x, center_y), 25.0f,
        IM_COL32(255, 215, 0, 255), 32, 3.0f);
    
    // Legend
    ImGui::SetCursorPosY(canvas_size.y - 60);
    ImGui::Text("Visualization: Divine Unity");
    ImGui::Text("Orbs: Divine Structures | Rays: Unity Connections | Center: Divine Core");
}

} // namespace DivineUnity
