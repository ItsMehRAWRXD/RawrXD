#include "PrimordialChaosPanel.hpp"
#include "PrimordialChaosEngine.hpp"
#include "PrimordialChaosLoop.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>

namespace PrimordialChaos {

// Static member definitions
bool PrimordialChaosPanel::s_initialized = false;
bool PrimordialChaosPanel::s_visible = true;
PrimordialChaosPanelTab PrimordialChaosPanel::s_activeTab = PrimordialChaosPanelTab::PrimordialStructure;
int PrimordialChaosPanel::s_dockingLocation = 1; // Right side by default

std::string PrimordialChaosPanel::s_selectedPrimordialId;
std::string PrimordialChaosPanel::s_selectedChaosId;
std::string PrimordialChaosPanel::s_selectedVoidId;
std::string PrimordialChaosPanel::s_selectedAbyssId;
std::string PrimordialChaosPanel::s_selectedFluxId;

PrimordialChaosPanel::StructureSelectedCallback PrimordialChaosPanel::s_structureCallback;
PrimordialChaosPanel::ChaosSelectedCallback PrimordialChaosPanel::s_chaosCallback;
PrimordialChaosPanel::VoidSelectedCallback PrimordialChaosPanel::s_voidCallback;
PrimordialChaosPanel::AbyssSelectedCallback PrimordialChaosPanel::s_abyssCallback;
PrimordialChaosPanel::FluxSelectedCallback PrimordialChaosPanel::s_fluxCallback;

nlohmann::json PrimordialChaosPanel::s_cachedMetrics;
std::vector<nlohmann::json> PrimordialChaosPanel::s_cachedStructures;
std::vector<nlohmann::json> PrimordialChaosPanel::s_cachedChaosPrimordials;
std::vector<nlohmann::json> PrimordialChaosPanel::s_cachedVoidPrimordials;
std::vector<nlohmann::json> PrimordialChaosPanel::s_cachedAbyssPrimordials;
std::vector<nlohmann::json> PrimordialChaosPanel::s_cachedFluxPrimordials;
std::chrono::steady_clock::time_point PrimordialChaosPanel::s_lastRefresh;

char PrimordialChaosPanel::s_newStructureName[256] = {};
char PrimordialChaosPanel::s_newChaosName[256] = {};
char PrimordialChaosPanel::s_newVoidName[256] = {};
char PrimordialChaosPanel::s_newAbyssName[256] = {};
char PrimordialChaosPanel::s_newFluxName[256] = {};

void PrimordialChaosPanel::Init() {
    if (s_initialized) return;
    
    // Register with loop for automatic refresh
    PrimordialChaosLoop::RegisterUpdateCallback([](float) {
        auto now = std::chrono::steady_clock::now();
        if (now - s_lastRefresh > std::chrono::seconds(1)) {
            RefreshData();
            s_lastRefresh = now;
        }
    });
    
    s_initialized = true;
    RefreshData();
}

void PrimordialChaosPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

bool PrimordialChaosPanel::IsInitialized() {
    return s_initialized;
}

void PrimordialChaosPanel::Render() {
    if (!s_visible) return;
    
    bool open = s_visible;
    Render(&open);
    s_visible = open;
}

void PrimordialChaosPanel::Render(bool* p_open) {
    if (!p_open || !*p_open) return;
    
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Primordial Chaos Panel##PrimordialChaos", p_open)) {
        // Tab bar
        if (ImGui::BeginTabBar("PrimordialChaosTabs")) {
            if (ImGui::BeginTabItem("Primordial Structure")) {
                s_activeTab = PrimordialChaosPanelTab::PrimordialStructure;
                RenderPrimordialStructureTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Chaos Primordial")) {
                s_activeTab = PrimordialChaosPanelTab::ChaosPrimordial;
                RenderChaosPrimordialTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Void Primordial")) {
                s_activeTab = PrimordialChaosPanelTab::VoidPrimordial;
                RenderVoidPrimordialTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Abyss Primordial")) {
                s_activeTab = PrimordialChaosPanelTab::AbyssPrimordial;
                RenderAbyssPrimordialTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Flux Primordial")) {
                s_activeTab = PrimordialChaosPanelTab::FluxPrimordial;
                RenderFluxPrimordialTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Metrics")) {
                s_activeTab = PrimordialChaosPanelTab::Metrics;
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Visualization")) {
                s_activeTab = PrimordialChaosPanelTab::Visualization;
                RenderVisualizationTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void PrimordialChaosPanel::Show() {
    s_visible = true;
}

void PrimordialChaosPanel::Hide() {
    s_visible = false;
}

void PrimordialChaosPanel::ToggleVisibility() {
    s_visible = !s_visible;
}

bool PrimordialChaosPanel::IsVisible() {
    return s_visible;
}

void PrimordialChaosPanel::SetActiveTab(PrimordialChaosPanelTab tab) {
    s_activeTab = tab;
}

PrimordialChaosPanelTab PrimordialChaosPanel::GetActiveTab() {
    return s_activeTab;
}

void PrimordialChaosPanel::SetStructureSelectedCallback(const StructureSelectedCallback& callback) {
    s_structureCallback = callback;
}

void PrimordialChaosPanel::SetChaosSelectedCallback(const ChaosSelectedCallback& callback) {
    s_chaosCallback = callback;
}

void PrimordialChaosPanel::SetVoidSelectedCallback(const VoidSelectedCallback& callback) {
    s_voidCallback = callback;
}

void PrimordialChaosPanel::SetAbyssSelectedCallback(const AbyssSelectedCallback& callback) {
    s_abyssCallback = callback;
}

void PrimordialChaosPanel::SetFluxSelectedCallback(const FluxSelectedCallback& callback) {
    s_fluxCallback = callback;
}

void PrimordialChaosPanel::RefreshData() {
    RefreshStructures();
    RefreshChaosPrimordials();
    RefreshVoidPrimordials();
    RefreshAbyssPrimordials();
    RefreshFluxPrimordials();
    s_cachedMetrics = PrimordialChaosEngine::GetPrimordialChaosMetrics();
}

void PrimordialChaosPanel::RefreshStructures() {
    s_cachedStructures.clear();
    auto structures = PrimordialChaosEngine::GetAllPrimordialChaosStructures();
    for (auto& s : structures) {
        s_cachedStructures.push_back(s.ToJson());
    }
}

void PrimordialChaosPanel::RefreshChaosPrimordials() {
    s_cachedChaosPrimordials.clear();
    auto chaosList = PrimordialChaosEngine::GetAllChaosPrimordials();
    for (auto& c : chaosList) {
        s_cachedChaosPrimordials.push_back(c.ToJson());
    }
}

void PrimordialChaosPanel::RefreshVoidPrimordials() {
    s_cachedVoidPrimordials.clear();
    auto voidList = PrimordialChaosEngine::GetAllVoidPrimordials();
    for (auto& v : voidList) {
        s_cachedVoidPrimordials.push_back(v.ToJson());
    }
}

void PrimordialChaosPanel::RefreshAbyssPrimordials() {
    s_cachedAbyssPrimordials.clear();
    auto abyssList = PrimordialChaosEngine::GetAllAbyssPrimordials();
    for (auto& a : abyssList) {
        s_cachedAbyssPrimordials.push_back(a.ToJson());
    }
}

void PrimordialChaosPanel::RefreshFluxPrimordials() {
    s_cachedFluxPrimordials.clear();
    auto fluxList = PrimordialChaosEngine::GetAllFluxPrimordials();
    for (auto& f : fluxList) {
        s_cachedFluxPrimordials.push_back(f.ToJson());
    }
}

nlohmann::json PrimordialChaosPanel::GetCurrentMetrics() {
    return s_cachedMetrics;
}

std::vector<nlohmann::json> PrimordialChaosPanel::GetCurrentStructures() {
    return s_cachedStructures;
}

std::vector<nlohmann::json> PrimordialChaosPanel::GetCurrentChaosPrimordials() {
    return s_cachedChaosPrimordials;
}

std::vector<nlohmann::json> PrimordialChaosPanel::GetCurrentVoidPrimordials() {
    return s_cachedVoidPrimordials;
}

std::vector<nlohmann::json> PrimordialChaosPanel::GetCurrentAbyssPrimordials() {
    return s_cachedAbyssPrimordials;
}

std::vector<nlohmann::json> PrimordialChaosPanel::GetCurrentFluxPrimordials() {
    return s_cachedFluxPrimordials;
}

void PrimordialChaosPanel::RegisterHotkey() {
    // Hotkey registration would be handled by IDE framework
    // Ctrl+Shift+F103 for Primordial Chaos Panel
}

void PrimordialChaosPanel::UnregisterHotkey() {
    // Unregister hotkey
}

void PrimordialChaosPanel::HandleHotkey() {
    ToggleVisibility();
}

void PrimordialChaosPanel::SetDockingLocation(int location) {
    s_dockingLocation = location;
}

int PrimordialChaosPanel::GetDockingLocation() {
    return s_dockingLocation;
}

// Tab renderers
void PrimordialChaosPanel::RenderPrimordialStructureTab() {
    ImGui::Columns(2, "PrimordialStructureColumns");
    
    // Left column - List
    ImGui::Text("Primordial Structures");
    ImGui::Separator();
    
    ImGui::InputText("New Structure Name", s_newStructureName, sizeof(s_newStructureName));
    if (ImGui::Button("Create Structure")) {
        if (strlen(s_newStructureName) > 0) {
            PrimordialChaosEngine::CreatePrimordialChaosStructure(s_newStructureName);
            memset(s_newStructureName, 0, sizeof(s_newStructureName));
            RefreshStructures();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedStructures) {
        std::string primordialId = s.value("primordialId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedPrimordialId == primordialId);
        
        if (ImGui::Selectable((name + "##" + primordialId).c_str(), isSelected)) {
            s_selectedPrimordialId = primordialId;
            if (s_structureCallback) s_structureCallback(primordialId);
        }
    }
    
    ImGui::NextColumn();
    
    // Right column - Details
    if (!s_selectedPrimordialId.empty()) {
        RenderStructureDetails(s_selectedPrimordialId);
    } else {
        ImGui::Text("Select a structure to view details");
    }
    
    ImGui::Columns(1);
}

void PrimordialChaosPanel::RenderStructureDetails(const std::string& primordialId) {
    auto structure = PrimordialChaosEngine::GetPrimordialChaosStructure(primordialId);
    if (!structure) return;
    
    ImGui::Text("Structure: %s", structure->name.c_str());
    ImGui::Text("ID: %s", structure->primordialId.c_str());
    ImGui::Separator();
    
    // Metrics
    ImGui::Text("Primordiality: %.2f", structure->primordiality);
    ImGui::ProgressBar(structure->primordiality, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Awaken Primordiality")) {
        PrimordialChaosEngine::AwakenPrimordiality(primordialId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Chaos: %.2f", structure->chaos);
    ImGui::ProgressBar(structure->chaos, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Unleash Chaos")) {
        PrimordialChaosEngine::UnleashChaos(primordialId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Void: %.2f", structure->voidness);
    ImGui::ProgressBar(structure->voidness, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Embrace Void")) {
        PrimordialChaosEngine::EmbraceVoid(primordialId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Abyss: %.2f", structure->abyss);
    ImGui::ProgressBar(structure->abyss, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Plumb Abyss")) {
        PrimordialChaosEngine::PlumbAbyss(primordialId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Flux: %.2f", structure->flux);
    ImGui::ProgressBar(structure->flux, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Channel Flux")) {
        PrimordialChaosEngine::ChannelFlux(primordialId, 0.1f);
    }
    
    if (ImGui::Button("Delete Structure", ImVec2(120, 0))) {
        PrimordialChaosEngine::DestroyPrimordialChaosStructure(primordialId);
        s_selectedPrimordialId.clear();
        RefreshStructures();
    }
}

void PrimordialChaosPanel::RenderChaosPrimordialTab() {
    ImGui::Columns(2, "ChaosPrimordialColumns");
    
    ImGui::Text("Chaos Primordials");
    ImGui::Separator();
    
    ImGui::InputText("New Chaos Name", s_newChaosName, sizeof(s_newChaosName));
    if (ImGui::Button("Create Chaos")) {
        if (strlen(s_newChaosName) > 0) {
            PrimordialChaosEngine::CreateChaosPrimordial(s_newChaosName);
            memset(s_newChaosName, 0, sizeof(s_newChaosName));
            RefreshChaosPrimordials();
        }
    }
    
    ImGui::Separator();
    
    for (auto& c : s_cachedChaosPrimordials) {
        std::string chaosId = c.value("chaosId", "");
        std::string name = c.value("name", "");
        bool isChaotic = c.value("isChaotic", false);
        bool isSelected = (s_selectedChaosId == chaosId);
        
        std::string label = name + (isChaotic ? " [Chaotic]" : "");
        if (ImGui::Selectable((label + "##" + chaosId).c_str(), isSelected)) {
            s_selectedChaosId = chaosId;
            if (s_chaosCallback) s_chaosCallback(chaosId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedChaosId.empty()) {
        RenderChaosDetails(s_selectedChaosId);
    } else {
        ImGui::Text("Select a chaos to view details");
    }
    
    ImGui::Columns(1);
}

void PrimordialChaosPanel::RenderChaosDetails(const std::string& chaosId) {
    auto chaos = PrimordialChaosEngine::GetChaosPrimordial(chaosId);
    if (!chaos) return;
    
    ImGui::Text("Chaos: %s", chaos->name.c_str());
    ImGui::Text("ID: %s", chaos->chaosId.c_str());
    ImGui::Text("Status: %s", chaos->isChaotic ? "Chaotic" : "Ordered");
    ImGui::Separator();
    
    ImGui::Text("Chaos: %.2f", chaos->chaos);
    ImGui::ProgressBar(chaos->chaos, ImVec2(-1, 0), "");
    
    ImGui::Text("Disorder: %.2f", chaos->disorder);
    ImGui::ProgressBar(chaos->disorder, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Sow Disorder")) {
        PrimordialChaosEngine::SowDisorder(chaosId, 0.1f);
    }
    
    ImGui::Text("Turbulence: %.2f", chaos->turbulence);
    ImGui::ProgressBar(chaos->turbulence, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Stir Turbulence")) {
        PrimordialChaosEngine::StirTurbulence(chaosId, 0.1f);
    }
    
    if (!chaos->isChaotic && ImGui::Button("Declare Chaotic")) {
        PrimordialChaosEngine::DeclareChaotic(chaosId);
        RefreshChaosPrimordials();
    }
    
    if (ImGui::Button("Delete Chaos", ImVec2(120, 0))) {
        PrimordialChaosEngine::DestroyChaosPrimordial(chaosId);
        s_selectedChaosId.clear();
        RefreshChaosPrimordials();
    }
}

void PrimordialChaosPanel::RenderVoidPrimordialTab() {
    ImGui::Columns(2, "VoidPrimordialColumns");
    
    ImGui::Text("Void Primordials");
    ImGui::Separator();
    
    ImGui::InputText("New Void Name", s_newVoidName, sizeof(s_newVoidName));
    if (ImGui::Button("Create Void")) {
        if (strlen(s_newVoidName) > 0) {
            PrimordialChaosEngine::CreateVoidPrimordial(s_newVoidName);
            memset(s_newVoidName, 0, sizeof(s_newVoidName));
            RefreshVoidPrimordials();
        }
    }
    
    ImGui::Separator();
    
    for (auto& v : s_cachedVoidPrimordials) {
        std::string voidId = v.value("voidId", "");
        std::string name = v.value("name", "");
        bool isSelected = (s_selectedVoidId == voidId);
        
        if (ImGui::Selectable((name + "##" + voidId).c_str(), isSelected)) {
            s_selectedVoidId = voidId;
            if (s_voidCallback) s_voidCallback(voidId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedVoidId.empty()) {
        RenderVoidDetails(s_selectedVoidId);
    } else {
        ImGui::Text("Select a void to view details");
    }
    
    ImGui::Columns(1);
}

void PrimordialChaosPanel::RenderVoidDetails(const std::string& voidId) {
    auto voidp = PrimordialChaosEngine::GetVoidPrimordial(voidId);
    if (!voidp) return;
    
    ImGui::Text("Void: %s", voidp->name.c_str());
    ImGui::Text("ID: %s", voidp->voidId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Void: %.2f", voidp->voidness);
    ImGui::ProgressBar(voidp->voidness, ImVec2(-1, 0), "");
    
    ImGui::Text("Emptiness: %.2f", voidp->emptiness);
    ImGui::ProgressBar(voidp->emptiness, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Deepen Emptiness")) {
        PrimordialChaosEngine::DeepenEmptiness(voidId, 0.1f);
    }
    
    ImGui::Text("Nullity: %.2f", voidp->nullity);
    ImGui::ProgressBar(voidp->nullity, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Embrace Nullity")) {
        PrimordialChaosEngine::EmbraceNullity(voidId, 0.1f);
    }
    
    if (ImGui::Button("Delete Void", ImVec2(120, 0))) {
        PrimordialChaosEngine::DestroyVoidPrimordial(voidId);
        s_selectedVoidId.clear();
        RefreshVoidPrimordials();
    }
}

void PrimordialChaosPanel::RenderAbyssPrimordialTab() {
    ImGui::Columns(2, "AbyssPrimordialColumns");
    
    ImGui::Text("Abyss Primordials");
    ImGui::Separator();
    
    ImGui::InputText("New Abyss Name", s_newAbyssName, sizeof(s_newAbyssName));
    if (ImGui::Button("Create Abyss")) {
        if (strlen(s_newAbyssName) > 0) {
            PrimordialChaosEngine::CreateAbyssPrimordial(s_newAbyssName);
            memset(s_newAbyssName, 0, sizeof(s_newAbyssName));
            RefreshAbyssPrimordials();
        }
    }
    
    ImGui::Separator();
    
    for (auto& a : s_cachedAbyssPrimordials) {
        std::string abyssId = a.value("abyssId", "");
        std::string name = a.value("name", "");
        bool isAbyssal = a.value("isAbyssal", false);
        bool isSelected = (s_selectedAbyssId == abyssId);
        
        std::string label = name + (isAbyssal ? " [Abyssal]" : "");
        if (ImGui::Selectable((label + "##" + abyssId).c_str(), isSelected)) {
            s_selectedAbyssId = abyssId;
            if (s_abyssCallback) s_abyssCallback(abyssId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedAbyssId.empty()) {
        RenderAbyssDetails(s_selectedAbyssId);
    } else {
        ImGui::Text("Select an abyss to view details");
    }
    
    ImGui::Columns(1);
}

void PrimordialChaosPanel::RenderAbyssDetails(const std::string& abyssId) {
    auto abyss = PrimordialChaosEngine::GetAbyssPrimordial(abyssId);
    if (!abyss) return;
    
    ImGui::Text("Abyss: %s", abyss->name.c_str());
    ImGui::Text("ID: %s", abyss->abyssId.c_str());
    ImGui::Text("Status: %s", abyss->isAbyssal ? "Abyssal" : "Shallow");
    ImGui::Separator();
    
    ImGui::Text("Abyss: %.2f", abyss->abyss);
    ImGui::ProgressBar(abyss->abyss, ImVec2(-1, 0), "");
    
    ImGui::Text("Depth: %.2f", abyss->depth);
    ImGui::ProgressBar(abyss->depth, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Fathom Depth")) {
        PrimordialChaosEngine::FathomDepth(abyssId, 0.1f);
    }
    
    ImGui::Text("Darkness: %.2f", abyss->darkness);
    ImGui::ProgressBar(abyss->darkness, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Shroud Darkness")) {
        PrimordialChaosEngine::ShroudDarkness(abyssId, 0.1f);
    }
    
    if (!abyss->isAbyssal && ImGui::Button("Declare Abyssal")) {
        PrimordialChaosEngine::DeclareAbyssal(abyssId);
        RefreshAbyssPrimordials();
    }
    
    if (ImGui::Button("Delete Abyss", ImVec2(120, 0))) {
        PrimordialChaosEngine::DestroyAbyssPrimordial(abyssId);
        s_selectedAbyssId.clear();
        RefreshAbyssPrimordials();
    }
}

void PrimordialChaosPanel::RenderFluxPrimordialTab() {
    ImGui::Columns(2, "FluxPrimordialColumns");
    
    ImGui::Text("Flux Primordials");
    ImGui::Separator();
    
    ImGui::InputText("New Flux Name", s_newFluxName, sizeof(s_newFluxName));
    if (ImGui::Button("Create Flux")) {
        if (strlen(s_newFluxName) > 0) {
            PrimordialChaosEngine::CreateFluxPrimordial(s_newFluxName);
            memset(s_newFluxName, 0, sizeof(s_newFluxName));
            RefreshFluxPrimordials();
        }
    }
    
    ImGui::Separator();
    
    for (auto& f : s_cachedFluxPrimordials) {
        std::string fluxId = f.value("fluxId", "");
        std::string name = f.value("name", "");
        bool isSelected = (s_selectedFluxId == fluxId);
        
        if (ImGui::Selectable((name + "##" + fluxId).c_str(), isSelected)) {
            s_selectedFluxId = fluxId;
            if (s_fluxCallback) s_fluxCallback(fluxId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedFluxId.empty()) {
        RenderFluxDetails(s_selectedFluxId);
    } else {
        ImGui::Text("Select a flux to view details");
    }
    
    ImGui::Columns(1);
}

void PrimordialChaosPanel::RenderFluxDetails(const std::string& fluxId) {
    auto flux = PrimordialChaosEngine::GetFluxPrimordial(fluxId);
    if (!flux) return;
    
    ImGui::Text("Flux: %s", flux->name.c_str());
    ImGui::Text("ID: %s", flux->fluxId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Flux: %.2f", flux->flux);
    ImGui::ProgressBar(flux->flux, ImVec2(-1, 0), "");
    
    ImGui::Text("Change: %.2f", flux->change);
    ImGui::ProgressBar(flux->change, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Accelerate Change")) {
        PrimordialChaosEngine::AccelerateChange(fluxId, 0.1f);
    }
    
    ImGui::Text("Flow: %.2f", flux->flow);
    ImGui::ProgressBar(flux->flow, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Direct Flow")) {
        PrimordialChaosEngine::DirectFlow(fluxId, 0.1f);
    }
    
    if (ImGui::Button("Delete Flux", ImVec2(120, 0))) {
        PrimordialChaosEngine::DestroyFluxPrimordial(fluxId);
        s_selectedFluxId.clear();
        RefreshFluxPrimordials();
    }
}

void PrimordialChaosPanel::RenderMetricsTab() {
    RenderMetricsDashboard();
}

void PrimordialChaosPanel::RenderMetricsDashboard() {
    ImGui::Text("Primordial Chaos Metrics");
    ImGui::Separator();
    
    if (s_cachedMetrics.empty()) {
        ImGui::Text("No metrics available");
        return;
    }
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Primordial Structures: %d", s_cachedMetrics.value("primordialStructureCount", 0));
    ImGui::Text("Chaos Primordials: %d", s_cachedMetrics.value("chaosPrimordialCount", 0));
    ImGui::Text("Void Primordials: %d", s_cachedMetrics.value("voidPrimordialCount", 0));
    ImGui::Text("Abyss Primordials: %d", s_cachedMetrics.value("abyssPrimordialCount", 0));
    ImGui::Text("Flux Primordials: %d", s_cachedMetrics.value("fluxPrimordialCount", 0));
    
    ImGui::NextColumn();
    
    float totalPrimordiality = s_cachedMetrics.value("totalPrimordiality", 0.0f);
    float totalChaos = s_cachedMetrics.value("totalChaos", 0.0f);
    float totalVoidness = s_cachedMetrics.value("totalVoidness", 0.0f);
    float totalAbyss = s_cachedMetrics.value("totalAbyss", 0.0f);
    float totalFlux = s_cachedMetrics.value("totalFlux", 0.0f);
    
    ImGui::Text("Total Primordiality: %.2f", totalPrimordiality);
    ImGui::Text("Total Chaos: %.2f", totalChaos);
    ImGui::Text("Total Void: %.2f", totalVoidness);
    ImGui::Text("Total Abyss: %.2f", totalAbyss);
    ImGui::Text("Total Flux: %.2f", totalFlux);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    
    int chaoticCount = s_cachedMetrics.value("chaoticCount", 0);
    int abyssalCount = s_cachedMetrics.value("abyssalCount", 0);
    
    ImGui::Text("Chaotic: %d", chaoticCount);
    ImGui::Text("Abyssal: %d", abyssalCount);
    
    // Loop metrics
    ImGui::Separator();
    ImGui::Text("Loop Metrics");
    ImGui::Text("TPS: %.1f", PrimordialChaosLoop::GetCurrentTPS());
    ImGui::Text("Tick Count: %lld", PrimordialChaosLoop::GetTickCount());
}

void PrimordialChaosPanel::RenderVisualizationTab() {
    RenderPrimordialVisualization();
}

void PrimordialChaosPanel::RenderPrimordialVisualization() {
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    // Background - dark void
    draw_list->AddRectFilled(canvas_pos, 
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(5, 5, 10, 255));
    
    float center_x = canvas_pos.x + canvas_size.x * 0.5f;
    float center_y = canvas_pos.y + canvas_size.y * 0.5f;
    
    // Draw primordial structures as chaotic orbs
    int idx = 0;
    for (auto& s : s_cachedStructures) {
        float primordiality = s.value("primordiality", 0.0f);
        float chaos = s.value("chaos", 0.0f);
        float voidness = s.value("voidness", 0.0f);
        float abyss = s.value("abyss", 0.0f);
        float flux = s.value("flux", 0.0f);
        
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)s_cachedStructures.size());
        float radius = 70.0f + (primordiality * 50.0f);
        
        float x = center_x + std::cos(angle) * radius;
        float y = center_y + std::sin(angle) * radius;
        
        float orb_size = 10.0f + (chaos * 15.0f);
        
        // Chaos glow effect
        for (int i = 4; i >= 0; i--) {
            float glow_size = orb_size + i * 5;
            int alpha = 40 - i * 7;
            draw_list->AddCircleFilled(ImVec2(x, y), glow_size,
                IM_COL32(150 + (int)(chaos * 105), 50, 200 + (int)(voidness * 55), alpha));
        }
        
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), orb_size,
            IM_COL32(200 + (int)(flux * 55), 100, 255, 255));
        
        // Abyss tendrils
        if (abyss > 0.3f) {
            float tendril_angle = angle + 3.14159f;
            float tendril_length = 20.0f + abyss * 30.0f;
            float end_x = x + std::cos(tendril_angle) * tendril_length;
            float end_y = y + std::sin(tendril_angle) * tendril_length;
            
            draw_list->AddLine(ImVec2(x, y), ImVec2(end_x, end_y),
                IM_COL32(50, 0, 100, 150), 2.0f);
        }
        
        idx++;
    }
    
    // Center primordial core
    draw_list->AddCircleFilled(ImVec2(center_x, center_y), 25.0f,
        IM_COL32(255, 255, 255, 200));
    draw_list->AddCircle(ImVec2(center_x, center_y), 25.0f,
        IM_COL32(200, 100, 255, 255), 32, 3.0f);
    
    // Legend
    ImGui::SetCursorPosY(canvas_size.y - 60);
    ImGui::Text("Visualization: Primordial Chaos");
    ImGui::Text("Orbs: Primordial Structures | Tendrils: Abyss Depth | Center: Chaos Core");
}

} // namespace PrimordialChaos
