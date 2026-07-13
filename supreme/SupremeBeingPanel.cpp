#include "SupremeBeingPanel.hpp"
#include "SupremeBeingEngine.hpp"
#include "SupremeBeingLoop.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>

namespace SupremeBeing {

// Static member definitions
bool SupremeBeingPanel::s_initialized = false;
bool SupremeBeingPanel::s_visible = true;
SupremeBeingPanelTab SupremeBeingPanel::s_activeTab = SupremeBeingPanelTab::SupremeStructure;
int SupremeBeingPanel::s_dockingLocation = 1;

std::string SupremeBeingPanel::s_selectedSupremeId;
std::string SupremeBeingPanel::s_selectedBeingId;
std::string SupremeBeingPanel::s_selectedEssenceId;
std::string SupremeBeingPanel::s_selectedNatureId;
std::string SupremeBeingPanel::s_selectedSpiritId;
std::string SupremeBeingPanel::s_selectedWillId;

SupremeBeingPanel::StructureSelectedCallback SupremeBeingPanel::s_structureCallback;
SupremeBeingPanel::BeingSelectedCallback SupremeBeingPanel::s_beingCallback;
SupremeBeingPanel::EssenceSelectedCallback SupremeBeingPanel::s_essenceCallback;
SupremeBeingPanel::NatureSelectedCallback SupremeBeingPanel::s_natureCallback;
SupremeBeingPanel::SpiritSelectedCallback SupremeBeingPanel::s_spiritCallback;
SupremeBeingPanel::WillSelectedCallback SupremeBeingPanel::s_willCallback;

nlohmann::json SupremeBeingPanel::s_cachedMetrics;
std::vector<nlohmann::json> SupremeBeingPanel::s_cachedStructures;
std::vector<nlohmann::json> SupremeBeingPanel::s_cachedBeingSupremes;
std::vector<nlohmann::json> SupremeBeingPanel::s_cachedEssenceSupremes;
std::vector<nlohmann::json> SupremeBeingPanel::s_cachedNatureSupremes;
std::vector<nlohmann::json> SupremeBeingPanel::s_cachedSpiritSupremes;
std::vector<nlohmann::json> SupremeBeingPanel::s_cachedWillSupremes;

char SupremeBeingPanel::s_newStructureName[256] = {};
char SupremeBeingPanel::s_newBeingName[256] = {};
char SupremeBeingPanel::s_newEssenceName[256] = {};
char SupremeBeingPanel::s_newNatureName[256] = {};
char SupremeBeingPanel::s_newSpiritName[256] = {};
char SupremeBeingPanel::s_newWillName[256] = {};

void SupremeBeingPanel::Init() {
    if (s_initialized) return;
    
    SupremeBeingLoop::RegisterUpdateCallback([](float) {
        auto now = std::chrono::steady_clock::now();
        static auto lastRefresh = std::chrono::steady_clock::now();
        if (now - lastRefresh > std::chrono::seconds(1)) {
            RefreshData();
            lastRefresh = now;
        }
    });
    
    s_initialized = true;
    RefreshData();
}

void SupremeBeingPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

bool SupremeBeingPanel::IsInitialized() {
    return s_initialized;
}

void SupremeBeingPanel::Render() {
    if (!s_visible) return;
    bool open = s_visible;
    Render(&open);
    s_visible = open;
}

void SupremeBeingPanel::Render(bool* p_open) {
    if (!p_open || !*p_open) return;
    
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Supreme Being Panel##SupremeBeing", p_open)) {
        if (ImGui::BeginTabBar("SupremeBeingTabs")) {
            if (ImGui::BeginTabItem("Supreme Structure")) {
                s_activeTab = SupremeBeingPanelTab::SupremeStructure;
                RenderSupremeStructureTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Being Supreme")) {
                s_activeTab = SupremeBeingPanelTab::BeingSupreme;
                RenderBeingSupremeTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Essence Supreme")) {
                s_activeTab = SupremeBeingPanelTab::EssenceSupreme;
                RenderEssenceSupremeTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Nature Supreme")) {
                s_activeTab = SupremeBeingPanelTab::NatureSupreme;
                RenderNatureSupremeTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Spirit Supreme")) {
                s_activeTab = SupremeBeingPanelTab::SpiritSupreme;
                RenderSpiritSupremeTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Will Supreme")) {
                s_activeTab = SupremeBeingPanelTab::WillSupreme;
                RenderWillSupremeTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Metrics")) {
                s_activeTab = SupremeBeingPanelTab::Metrics;
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Visualization")) {
                s_activeTab = SupremeBeingPanelTab::Visualization;
                RenderVisualizationTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void SupremeBeingPanel::Show() { s_visible = true; }
void SupremeBeingPanel::Hide() { s_visible = false; }
void SupremeBeingPanel::ToggleVisibility() { s_visible = !s_visible; }
bool SupremeBeingPanel::IsVisible() { return s_visible; }

void SupremeBeingPanel::SetActiveTab(SupremeBeingPanelTab tab) { s_activeTab = tab; }
SupremeBeingPanelTab SupremeBeingPanel::GetActiveTab() { return s_activeTab; }

void SupremeBeingPanel::SetStructureSelectedCallback(const StructureSelectedCallback& callback) { s_structureCallback = callback; }
void SupremeBeingPanel::SetBeingSelectedCallback(const BeingSelectedCallback& callback) { s_beingCallback = callback; }
void SupremeBeingPanel::SetEssenceSelectedCallback(const EssenceSelectedCallback& callback) { s_essenceCallback = callback; }
void SupremeBeingPanel::SetNatureSelectedCallback(const NatureSelectedCallback& callback) { s_natureCallback = callback; }
void SupremeBeingPanel::SetSpiritSelectedCallback(const SpiritSelectedCallback& callback) { s_spiritCallback = callback; }
void SupremeBeingPanel::SetWillSelectedCallback(const WillSelectedCallback& callback) { s_willCallback = callback; }

void SupremeBeingPanel::RefreshData() {
    RefreshStructures();
    RefreshBeingSupremes();
    RefreshEssenceSupremes();
    RefreshNatureSupremes();
    RefreshSpiritSupremes();
    RefreshWillSupremes();
    s_cachedMetrics = SupremeBeingEngine::GetSupremeBeingMetrics();
}

void SupremeBeingPanel::RefreshStructures() {
    s_cachedStructures.clear();
    auto structures = SupremeBeingEngine::GetAllSupremeBeingStructures();
    for (auto& s : structures) s_cachedStructures.push_back(s.ToJson());
}

void SupremeBeingPanel::RefreshBeingSupremes() {
    s_cachedBeingSupremes.clear();
    auto beingList = SupremeBeingEngine::GetAllBeingSupremes();
    for (auto& b : beingList) s_cachedBeingSupremes.push_back(b.ToJson());
}

void SupremeBeingPanel::RefreshEssenceSupremes() {
    s_cachedEssenceSupremes.clear();
    auto essenceList = SupremeBeingEngine::GetAllEssenceSupremes();
    for (auto& e : essenceList) s_cachedEssenceSupremes.push_back(e.ToJson());
}

void SupremeBeingPanel::RefreshNatureSupremes() {
    s_cachedNatureSupremes.clear();
    auto natureList = SupremeBeingEngine::GetAllNatureSupremes();
    for (auto& n : natureList) s_cachedNatureSupremes.push_back(n.ToJson());
}

void SupremeBeingPanel::RefreshSpiritSupremes() {
    s_cachedSpiritSupremes.clear();
    auto spiritList = SupremeBeingEngine::GetAllSpiritSupremes();
    for (auto& s : spiritList) s_cachedSpiritSupremes.push_back(s.ToJson());
}

void SupremeBeingPanel::RefreshWillSupremes() {
    s_cachedWillSupremes.clear();
    auto willList = SupremeBeingEngine::GetAllWillSupremes();
    for (auto& w : willList) s_cachedWillSupremes.push_back(w.ToJson());
}

nlohmann::json SupremeBeingPanel::GetCurrentMetrics() { return s_cachedMetrics; }
std::vector<nlohmann::json> SupremeBeingPanel::GetCurrentStructures() { return s_cachedStructures; }
std::vector<nlohmann::json> SupremeBeingPanel::GetCurrentBeingSupremes() { return s_cachedBeingSupremes; }
std::vector<nlohmann::json> SupremeBeingPanel::GetCurrentEssenceSupremes() { return s_cachedEssenceSupremes; }
std::vector<nlohmann::json> SupremeBeingPanel::GetCurrentNatureSupremes() { return s_cachedNatureSupremes; }
std::vector<nlohmann::json> SupremeBeingPanel::GetCurrentSpiritSupremes() { return s_cachedSpiritSupremes; }
std::vector<nlohmann::json> SupremeBeingPanel::GetCurrentWillSupremes() { return s_cachedWillSupremes; }

void SupremeBeingPanel::RegisterHotkey() {}
void SupremeBeingPanel::UnregisterHotkey() {}
void SupremeBeingPanel::HandleHotkey() { ToggleVisibility(); }
void SupremeBeingPanel::SetDockingLocation(int location) { s_dockingLocation = location; }
int SupremeBeingPanel::GetDockingLocation() { return s_dockingLocation; }

void SupremeBeingPanel::RenderSupremeStructureTab() {
    ImGui::Columns(2, "SupremeStructureColumns");
    
    ImGui::Text("Supreme Structures");
    ImGui::Separator();
    
    ImGui::InputText("New Structure Name", s_newStructureName, sizeof(s_newStructureName));
    if (ImGui::Button("Create Structure")) {
        if (strlen(s_newStructureName) > 0) {
            SupremeBeingEngine::CreateSupremeBeingStructure(s_newStructureName);
            memset(s_newStructureName, 0, sizeof(s_newStructureName));
            RefreshStructures();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedStructures) {
        std::string supremeId = s.value("supremeId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedSupremeId == supremeId);
        
        if (ImGui::Selectable((name + "##" + supremeId).c_str(), isSelected)) {
            s_selectedSupremeId = supremeId;
            if (s_structureCallback) s_structureCallback(supremeId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedSupremeId.empty()) {
        RenderStructureDetails(s_selectedSupremeId);
    } else {
        ImGui::Text("Select a structure to view details");
    }
    
    ImGui::Columns(1);
}

void SupremeBeingPanel::RenderStructureDetails(const std::string& supremeId) {
    auto structure = SupremeBeingEngine::GetSupremeBeingStructure(supremeId);
    if (!structure) return;
    
    ImGui::Text("Structure: %s", structure->name.c_str());
    ImGui::Text("ID: %s", structure->supremeId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Supremeness: %.2f", structure->supremeness);
    ImGui::ProgressBar(structure->supremeness, ImVec2(-1, 0), "");
    if (ImGui::Button("Expand Supremeness")) SupremeBeingEngine::ExpandSupremeness(supremeId, 0.1f);
    
    ImGui::Text("Being: %.2f", structure->being);
    ImGui::ProgressBar(structure->being, ImVec2(-1, 0), "");
    if (ImGui::Button("Deepen Being")) SupremeBeingEngine::DeepenBeing(supremeId, 0.1f);
    
    ImGui::Text("Essence: %.2f", structure->essence);
    ImGui::ProgressBar(structure->essence, ImVec2(-1, 0), "");
    if (ImGui::Button("Cultivate Essence")) SupremeBeingEngine::CultivateEssence(supremeId, 0.1f);
    
    ImGui::Text("Nature: %.2f", structure->nature);
    ImGui::ProgressBar(structure->nature, ImVec2(-1, 0), "");
    if (ImGui::Button("Refine Nature")) SupremeBeingEngine::RefineNature(supremeId, 0.1f);
    
    ImGui::Text("Spirit: %.2f", structure->spirit);
    ImGui::ProgressBar(structure->spirit, ImVec2(-1, 0), "");
    if (ImGui::Button("Elevate Spirit")) SupremeBeingEngine::ElevateSpirit(supremeId, 0.1f);
    
    ImGui::Text("Will: %.2f", structure->will);
    ImGui::ProgressBar(structure->will, ImVec2(-1, 0), "");
    if (ImGui::Button("Strengthen Will")) SupremeBeingEngine::StrengthenWill(supremeId, 0.1f);
    
    if (ImGui::Button("Delete Structure", ImVec2(120, 0))) {
        SupremeBeingEngine::DestroySupremeBeingStructure(supremeId);
        s_selectedSupremeId.clear();
        RefreshStructures();
    }
}

void SupremeBeingPanel::RenderBeingSupremeTab() {
    ImGui::Columns(2, "BeingSupremeColumns");
    
    ImGui::Text("Being Supremes");
    ImGui::Separator();
    
    ImGui::InputText("New Being Name", s_newBeingName, sizeof(s_newBeingName));
    if (ImGui::Button("Create Being")) {
        if (strlen(s_newBeingName) > 0) {
            SupremeBeingEngine::CreateBeingSupreme(s_newBeingName);
            memset(s_newBeingName, 0, sizeof(s_newBeingName));
            RefreshBeingSupremes();
        }
    }
    
    ImGui::Separator();
    
    for (auto& b : s_cachedBeingSupremes) {
        std::string beingId = b.value("beingId", "");
        std::string name = b.value("name", "");
        bool isBeing = b.value("isBeing", false);
        bool isSelected = (s_selectedBeingId == beingId);
        
        std::string label = name + (isBeing ? " [Being]" : "");
        if (ImGui::Selectable((label + "##" + beingId).c_str(), isSelected)) {
            s_selectedBeingId = beingId;
            if (s_beingCallback) s_beingCallback(beingId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedBeingId.empty()) {
        RenderBeingDetails(s_selectedBeingId);
    } else {
        ImGui::Text("Select a being to view details");
    }
    
    ImGui::Columns(1);
}

void SupremeBeingPanel::RenderBeingDetails(const std::string& beingId) {
    auto being = SupremeBeingEngine::GetBeingSupreme(beingId);
    if (!being) return;
    
    ImGui::Text("Being: %s", being->name.c_str());
    ImGui::Text("ID: %s", being->beingId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Being: %.2f", being->being);
    ImGui::ProgressBar(being->being, ImVec2(-1, 0), "");
    
    ImGui::Text("Existence: %.2f", being->existence);
    ImGui::ProgressBar(being->existence, ImVec2(-1, 0), "");
    if (ImGui::Button("Affirm Existence")) SupremeBeingEngine::AffirmExistence(beingId, 0.1f);
    
    ImGui::Text("Presence: %.2f", being->presence);
    ImGui::ProgressBar(being->presence, ImVec2(-1, 0), "");
    if (ImGui::Button("Manifest Presence")) SupremeBeingEngine::ManifestPresence(beingId, 0.1f);
    
    if (!being->isBeing && ImGui::Button("Declare Being")) {
        SupremeBeingEngine::DeclareBeing(beingId);
        RefreshBeingSupremes();
    }
    
    if (ImGui::Button("Delete Being", ImVec2(120, 0))) {
        SupremeBeingEngine::DestroyBeingSupreme(beingId);
        s_selectedBeingId.clear();
        RefreshBeingSupremes();
    }
}

void SupremeBeingPanel::RenderEssenceSupremeTab() {
    ImGui::Columns(2, "EssenceSupremeColumns");
    
    ImGui::Text("Essence Supremes");
    ImGui::Separator();
    
    ImGui::InputText("New Essence Name", s_newEssenceName, sizeof(s_newEssenceName));
    if (ImGui::Button("Create Essence")) {
        if (strlen(s_newEssenceName) > 0) {
            SupremeBeingEngine::CreateEssenceSupreme(s_newEssenceName);
            memset(s_newEssenceName, 0, sizeof(s_newEssenceName));
            RefreshEssenceSupremes();
        }
    }
    
    ImGui::Separator();
    
    for (auto& e : s_cachedEssenceSupremes) {
        std::string essenceId = e.value("essenceId", "");
        std::string name = e.value("name", "");
        bool isEssence = e.value("isEssence", false);
        bool isSelected = (s_selectedEssenceId == essenceId);
        
        std::string label = name + (isEssence ? " [Essence]" : "");
        if (ImGui::Selectable((label + "##" + essenceId).c_str(), isSelected)) {
            s_selectedEssenceId = essenceId;
            if (s_essenceCallback) s_essenceCallback(essenceId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedEssenceId.empty()) {
        RenderEssenceDetails(s_selectedEssenceId);
    } else {
        ImGui::Text("Select an essence to view details");
    }
    
    ImGui::Columns(1);
}

void SupremeBeingPanel::RenderEssenceDetails(const std::string& essenceId) {
    auto essence = SupremeBeingEngine::GetEssenceSupreme(essenceId);
    if (!essence) return;
    
    ImGui::Text("Essence: %s", essence->name.c_str());
    ImGui::Text("ID: %s", essence->essenceId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Essence: %.2f", essence->essence);
    ImGui::ProgressBar(essence->essence, ImVec2(-1, 0), "");
    
    ImGui::Text("Substance: %.2f", essence->substance);
    ImGui::ProgressBar(essence->substance, ImVec2(-1, 0), "");
    if (ImGui::Button("Deepen Substance")) SupremeBeingEngine::DeepenSubstance(essenceId, 0.1f);
    
    ImGui::Text("Core: %.2f", essence->core);
    ImGui::ProgressBar(essence->core, ImVec2(-1, 0), "");
    if (ImGui::Button("Strengthen Core")) SupremeBeingEngine::StrengthenCore(essenceId, 0.1f);
    
    if (!essence->isEssence && ImGui::Button("Declare Essence")) {
        SupremeBeingEngine::DeclareEssence(essenceId);
        RefreshEssenceSupremes();
    }
    
    if (ImGui::Button("Delete Essence", ImVec2(120, 0))) {
        SupremeBeingEngine::DestroyEssenceSupreme(essenceId);
        s_selectedEssenceId.clear();
        RefreshEssenceSupremes();
    }
}

void SupremeBeingPanel::RenderNatureSupremeTab() {
    ImGui::Columns(2, "NatureSupremeColumns");
    
    ImGui::Text("Nature Supremes");
    ImGui::Separator();
    
    ImGui::InputText("New Nature Name", s_newNatureName, sizeof(s_newNatureName));
    if (ImGui::Button("Create Nature")) {
        if (strlen(s_newNatureName) > 0) {
            SupremeBeingEngine::CreateNatureSupreme(s_newNatureName);
            memset(s_newNatureName, 0, sizeof(s_newNatureName));
            RefreshNatureSupremes();
        }
    }
    
    ImGui::Separator();
    
    for (auto& n : s_cachedNatureSupremes) {
        std::string natureId = n.value("natureId", "");
        std::string name = n.value("name", "");
        bool isNatural = n.value("isNatural", false);
        bool isSelected = (s_selectedNatureId == natureId);
        
        std::string label = name + (isNatural ? " [Natural]" : "");
        if (ImGui::Selectable((label + "##" + natureId).c_str(), isSelected)) {
            s_selectedNatureId = natureId;
            if (s_natureCallback) s_natureCallback(natureId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedNatureId.empty()) {
        RenderNatureDetails(s_selectedNatureId);
    } else {
        ImGui::Text("Select a nature to view details");
    }
    
    ImGui::Columns(1);
}

void SupremeBeingPanel::RenderNatureDetails(const std::string& natureId) {
    auto nature = SupremeBeingEngine::GetNatureSupreme(natureId);
    if (!nature) return;
    
    ImGui::Text("Nature: %s", nature->name.c_str());
    ImGui::Text("ID: %s", nature->natureId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Nature: %.2f", nature->nature);
    ImGui::ProgressBar(nature->nature, ImVec2(-1, 0), "");
    
    ImGui::Text("Character: %.2f", nature->character);
    ImGui::ProgressBar(nature->character, ImVec2(-1, 0), "");
    if (ImGui::Button("Develop Character")) SupremeBeingEngine::DevelopCharacter(natureId, 0.1f);
    
    ImGui::Text("Quality: %.2f", nature->quality);
    ImGui::ProgressBar(nature->quality, ImVec2(-1, 0), "");
    if (ImGui::Button("Enhance Quality")) SupremeBeingEngine::EnhanceQuality(natureId, 0.1f);
    
    if (!nature->isNatural && ImGui::Button("Declare Natural")) {
        SupremeBeingEngine::DeclareNatural(natureId);
        RefreshNatureSupremes();
    }
    
    if (ImGui::Button("Delete Nature", ImVec2(120, 0))) {
        SupremeBeingEngine::DestroyNatureSupreme(natureId);
        s_selectedNatureId.clear();
        RefreshNatureSupremes();
    }
}

void SupremeBeingPanel::RenderSpiritSupremeTab() {
    ImGui::Columns(2, "SpiritSupremeColumns");
    
    ImGui::Text("Spirit Supremes");
    ImGui::Separator();
    
    ImGui::InputText("New Spirit Name", s_newSpiritName, sizeof(s_newSpiritName));
    if (ImGui::Button("Create Spirit")) {
        if (strlen(s_newSpiritName) > 0) {
            SupremeBeingEngine::CreateSpiritSupreme(s_newSpiritName);
            memset(s_newSpiritName, 0, sizeof(s_newSpiritName));
            RefreshSpiritSupremes();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedSpiritSupremes) {
        std::string spiritId = s.value("spiritId", "");
        std::string name = s.value("name", "");
        bool isSpiritual = s.value("isSpiritual", false);
        bool isSelected = (s_selectedSpiritId == spiritId);
        
        std::string label = name + (isSpiritual ? " [Spiritual]" : "");
        if (ImGui::Selectable((label + "##" + spiritId).c_str(), isSelected)) {
            s_selectedSpiritId = spiritId;
            if (s_spiritCallback) s_spiritCallback(spiritId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedSpiritId.empty()) {
        RenderSpiritDetails(s_selectedSpiritId);
    } else {
        ImGui::Text("Select a spirit to view details");
    }
    
    ImGui::Columns(1);
}

void SupremeBeingPanel::RenderSpiritDetails(const std::string& spiritId) {
    auto spirit = SupremeBeingEngine::GetSpiritSupreme(spiritId);
    if (!spirit) return;
    
    ImGui::Text("Spirit: %s", spirit->name.c_str());
    ImGui::Text("ID: %s", spirit->spiritId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Spirit: %.2f", spirit->spirit);
    ImGui::ProgressBar(spirit->spirit, ImVec2(-1, 0), "");
    
    ImGui::Text("Soul: %.2f", spirit->soul);
    ImGui::ProgressBar(spirit->soul, ImVec2(-1, 0), "");
    if (ImGui::Button("Nurture Soul")) SupremeBeingEngine::NurtureSoul(spiritId, 0.1f);
    
    ImGui::Text("Consciousness: %.2f", spirit->consciousness);
    ImGui::ProgressBar(spirit->consciousness, ImVec2(-1, 0), "");
    if (ImGui::Button("Expand Consciousness")) SupremeBeingEngine::ExpandConsciousness(spiritId, 0.1f);
    
    if (!spirit->isSpiritual && ImGui::Button("Declare Spiritual")) {
        SupremeBeingEngine::DeclareSpiritual(spiritId);
        RefreshSpiritSupremes();
    }
    
    if (ImGui::Button("Delete Spirit", ImVec2(120, 0))) {
        SupremeBeingEngine::DestroySpiritSupreme(spiritId);
        s_selectedSpiritId.clear();
        RefreshSpiritSupremes();
    }
}

void SupremeBeingPanel::RenderWillSupremeTab() {
    ImGui::Columns(2, "WillSupremeColumns");
    
    ImGui::Text("Will Supremes");
    ImGui::Separator();
    
    ImGui::InputText("New Will Name", s_newWillName, sizeof(s_newWillName));
    if (ImGui::Button("Create Will")) {
        if (strlen(s_newWillName) > 0) {
            SupremeBeingEngine::CreateWillSupreme(s_newWillName);
            memset(s_newWillName, 0, sizeof(s_newWillName));
            RefreshWillSupremes();
        }
    }
    
    ImGui::Separator();
    
    for (auto& w : s_cachedWillSupremes) {
        std::string willId = w.value("willId", "");
        std::string name = w.value("name", "");
        bool isWilling = w.value("isWilling", false);
        bool isSelected = (s_selectedWillId == willId);
        
        std::string label = name + (isWilling ? " [Willing]" : "");
        if (ImGui::Selectable((label + "##" + willId).c_str(), isSelected)) {
            s_selectedWillId = willId;
            if (s_willCallback) s_willCallback(willId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedWillId.empty()) {
        RenderWillDetails(s_selectedWillId);
    } else {
        ImGui::Text("Select a will to view details");
    }
    
    ImGui::Columns(1);
}

void SupremeBeingPanel::RenderWillDetails(const std::string& willId) {
    auto will = SupremeBeingEngine::GetWillSupreme(willId);
    if (!will) return;
    
    ImGui::Text("Will: %s", will->name.c_str());
    ImGui::Text("ID: %s", will->willId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Will: %.2f", will->will);
    ImGui::ProgressBar(will->will, ImVec2(-1, 0), "");
    
    ImGui::Text("Determination: %.2f", will->determination);
    ImGui::ProgressBar(will->determination, ImVec2(-1, 0), "");
    if (ImGui::Button("Fortify Determination")) SupremeBeingEngine::FortifyDetermination(willId, 0.1f);
    
    ImGui::Text("Resolve: %.2f", will->resolve);
    ImGui::ProgressBar(will->resolve, ImVec2(-1, 0), "");
    if (ImGui::Button("Cement Resolve")) SupremeBeingEngine::CementResolve(willId, 0.1f);
    
    if (!will->isWilling && ImGui::Button("Declare Willing")) {
        SupremeBeingEngine::DeclareWilling(willId);
        RefreshWillSupremes();
    }
    
    if (ImGui::Button("Delete Will", ImVec2(120, 0))) {
        SupremeBeingEngine::DestroyWillSupreme(willId);
        s_selectedWillId.clear();
        RefreshWillSupremes();
    }
}

void SupremeBeingPanel::RenderMetricsTab() {
    RenderMetricsDashboard();
}

void SupremeBeingPanel::RenderMetricsDashboard() {
    ImGui::Text("Supreme Being Metrics");
    ImGui::Separator();
    
    if (s_cachedMetrics.empty()) {
        ImGui::Text("No metrics available");
        return;
    }
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Supreme Structures: %d", s_cachedMetrics.value("supremeStructureCount", 0));
    ImGui::Text("Being Supremes: %d", s_cachedMetrics.value("beingSupremeCount", 0));
    ImGui::Text("Essence Supremes: %d", s_cachedMetrics.value("essenceSupremeCount", 0));
    ImGui::Text("Nature Supremes: %d", s_cachedMetrics.value("natureSupremeCount", 0));
    ImGui::Text("Spirit Supremes: %d", s_cachedMetrics.value("spiritSupremeCount", 0));
    ImGui::Text("Will Supremes: %d", s_cachedMetrics.value("willSupremeCount", 0));
    
    ImGui::NextColumn();
    
    float totalSupremeness = s_cachedMetrics.value("totalSupremeness", 0.0f);
    float totalBeing = s_cachedMetrics.value("totalBeing", 0.0f);
    float totalEssence = s_cachedMetrics.value("totalEssence", 0.0f);
    float totalNature = s_cachedMetrics.value("totalNature", 0.0f);
    float totalSpirit = s_cachedMetrics.value("totalSpirit", 0.0f);
    float totalWill = s_cachedMetrics.value("totalWill", 0.0f);
    
    ImGui::Text("Total Supremeness: %.2f", totalSupremeness);
    ImGui::Text("Total Being: %.2f", totalBeing);
    ImGui::Text("Total Essence: %.2f", totalEssence);
    ImGui::Text("Total Nature: %.2f", totalNature);
    ImGui::Text("Total Spirit: %.2f", totalSpirit);
    ImGui::Text("Total Will: %.2f", totalWill);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    
    int supremeCount = s_cachedMetrics.value("supremeCount", 0);
    ImGui::Text("Supreme: %d", supremeCount);
    
    ImGui::Separator();
    ImGui::Text("Loop Metrics");
    ImGui::Text("TPS: %.1f", SupremeBeingLoop::GetCurrentTPS());
    ImGui::Text("Tick Count: %lld", SupremeBeingLoop::GetTickCount());
}

void SupremeBeingPanel::RenderVisualizationTab() {
    RenderSupremeVisualization();
}

void SupremeBeingPanel::RenderSupremeVisualization() {
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    // Background - supreme gradient
    draw_list->AddRectFilled(canvas_pos, 
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(30, 25, 60, 255));
    
    float center_x = canvas_pos.x + canvas_size.x * 0.5f;
    float center_y = canvas_pos.y + canvas_size.y * 0.5f;
    
    // Draw supreme structures as being orbs
    int idx = 0;
    for (auto& s : s_cachedStructures) {
        float supremeness = s.value("supremeness", 0.0f);
        float being = s.value("being", 0.0f);
        float essence = s.value("essence", 0.0f);
        float nature = s.value("nature", 0.0f);
        float spirit = s.value("spirit", 0.0f);
        float will = s.value("will", 0.0f);
        
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)s_cachedStructures.size());
        float radius = 80.0f + (supremeness * 60.0f);
        
        float x = center_x + std::cos(angle) * radius;
        float y = center_y + std::sin(angle) * radius;
        
        float orb_size = 12.0f + (being * 18.0f);
        
        // Being glow effect
        for (int i = 4; i >= 0; i--) {
            float glow_size = orb_size + i * 6;
            int alpha = 50 - i * 10;
            draw_list->AddCircleFilled(ImVec2(x, y), glow_size,
                IM_COL32(220 + (int)(essence * 35), 200 + (int)(nature * 55), 255, alpha));
        }
        
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), orb_size,
            IM_COL32(240, 230, 255, 255));
        
        // Spirit ring
        if (spirit > 0.3f) {
            float ring_radius = orb_size + 8.0f + spirit * 10.0f;
            draw_list->AddCircle(ImVec2(x, y), ring_radius,
                IM_COL32(255, 220, 180, 150), 32, 2.0f);
        }
        
        // Will aura
        if (will > 0.5f) {
            float aura_radius = orb_size + 20.0f + will * 15.0f;
            draw_list->AddCircle(ImVec2(x, y), aura_radius,
                IM_COL32(255, 200, 100, 100), 32, 3.0f);
        }
        
        idx++;
    }
    
    // Center supreme core
    draw_list->AddCircleFilled(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(255, 255, 255, 220));
    draw_list->AddCircle(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(240, 220, 255, 255), 32, 4.0f);
    
    // Legend
    ImGui::SetCursorPosY(canvas_size.y - 60);
    ImGui::Text("Visualization: Supreme Being");
    ImGui::Text("Orbs: Supreme Structures | Rings: Spirit | Center: Supreme Core");
}

} // namespace SupremeBeing
