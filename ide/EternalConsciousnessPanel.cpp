#include "EternalConsciousnessPanel.hpp"
#include "EternalConsciousnessEngine.hpp"
#include "EternalConsciousnessLoop.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>

namespace EternalConsciousness {

// Static member definitions
bool EternalConsciousnessPanel::s_initialized = false;
bool EternalConsciousnessPanel::s_visible = true;
EternalConsciousnessPanelTab EternalConsciousnessPanel::s_activeTab = EternalConsciousnessPanelTab::EternalStructure;
int EternalConsciousnessPanel::s_dockingLocation = 1;

std::string EternalConsciousnessPanel::s_selectedEternalId;
std::string EternalConsciousnessPanel::s_selectedConsciousnessId;
std::string EternalConsciousnessPanel::s_selectedAwarenessId;
std::string EternalConsciousnessPanel::s_selectedPresenceId;
std::string EternalConsciousnessPanel::s_selectedExistenceId;
std::string EternalConsciousnessPanel::s_selectedContinuityId;

EternalConsciousnessPanel::StructureSelectedCallback EternalConsciousnessPanel::s_structureCallback;
EternalConsciousnessPanel::ConsciousnessSelectedCallback EternalConsciousnessPanel::s_consciousnessCallback;
EternalConsciousnessPanel::AwarenessSelectedCallback EternalConsciousnessPanel::s_awarenessCallback;
EternalConsciousnessPanel::PresenceSelectedCallback EternalConsciousnessPanel::s_presenceCallback;
EternalConsciousnessPanel::ExistenceSelectedCallback EternalConsciousnessPanel::s_existenceCallback;
EternalConsciousnessPanel::ContinuitySelectedCallback EternalConsciousnessPanel::s_continuityCallback;

nlohmann::json EternalConsciousnessPanel::s_cachedMetrics;
std::vector<nlohmann::json> EternalConsciousnessPanel::s_cachedStructures;
std::vector<nlohmann::json> EternalConsciousnessPanel::s_cachedConsciousnessEternals;
std::vector<nlohmann::json> EternalConsciousnessPanel::s_cachedAwarenessEternals;
std::vector<nlohmann::json> EternalConsciousnessPanel::s_cachedPresenceEternals;
std::vector<nlohmann::json> EternalConsciousnessPanel::s_cachedExistenceEternals;
std::vector<nlohmann::json> EternalConsciousnessPanel::s_cachedContinuityEternals;

char EternalConsciousnessPanel::s_newStructureName[256] = {};
char EternalConsciousnessPanel::s_newConsciousnessName[256] = {};
char EternalConsciousnessPanel::s_newAwarenessName[256] = {};
char EternalConsciousnessPanel::s_newPresenceName[256] = {};
char EternalConsciousnessPanel::s_newExistenceName[256] = {};
char EternalConsciousnessPanel::s_newContinuityName[256] = {};

void EternalConsciousnessPanel::Init() {
    if (s_initialized) return;
    
    EternalConsciousnessLoop::RegisterUpdateCallback([](float) {
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

void EternalConsciousnessPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

bool EternalConsciousnessPanel::IsInitialized() {
    return s_initialized;
}

void EternalConsciousnessPanel::Render() {
    if (!s_visible) return;
    bool open = s_visible;
    Render(&open);
    s_visible = open;
}

void EternalConsciousnessPanel::Render(bool* p_open) {
    if (!p_open || !*p_open) return;
    
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Eternal Consciousness Panel##EternalConsciousness", p_open)) {
        if (ImGui::BeginTabBar("EternalConsciousnessTabs")) {
            if (ImGui::BeginTabItem("Eternal Structure")) {
                s_activeTab = EternalConsciousnessPanelTab::EternalStructure;
                RenderEternalStructureTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Consciousness Eternal")) {
                s_activeTab = EternalConsciousnessPanelTab::ConsciousnessEternal;
                RenderConsciousnessEternalTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Awareness Eternal")) {
                s_activeTab = EternalConsciousnessPanelTab::AwarenessEternal;
                RenderAwarenessEternalTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Presence Eternal")) {
                s_activeTab = EternalConsciousnessPanelTab::PresenceEternal;
                RenderPresenceEternalTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Existence Eternal")) {
                s_activeTab = EternalConsciousnessPanelTab::ExistenceEternal;
                RenderExistenceEternalTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Continuity Eternal")) {
                s_activeTab = EternalConsciousnessPanelTab::ContinuityEternal;
                RenderContinuityEternalTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Metrics")) {
                s_activeTab = EternalConsciousnessPanelTab::Metrics;
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Visualization")) {
                s_activeTab = EternalConsciousnessPanelTab::Visualization;
                RenderVisualizationTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void EternalConsciousnessPanel::Show() { s_visible = true; }
void EternalConsciousnessPanel::Hide() { s_visible = false; }
void EternalConsciousnessPanel::ToggleVisibility() { s_visible = !s_visible; }
bool EternalConsciousnessPanel::IsVisible() { return s_visible; }

void EternalConsciousnessPanel::SetActiveTab(EternalConsciousnessPanelTab tab) { s_activeTab = tab; }
EternalConsciousnessPanelTab EternalConsciousnessPanel::GetActiveTab() { return s_activeTab; }

void EternalConsciousnessPanel::SetStructureSelectedCallback(const StructureSelectedCallback& callback) { s_structureCallback = callback; }
void EternalConsciousnessPanel::SetConsciousnessSelectedCallback(const ConsciousnessSelectedCallback& callback) { s_consciousnessCallback = callback; }
void EternalConsciousnessPanel::SetAwarenessSelectedCallback(const AwarenessSelectedCallback& callback) { s_awarenessCallback = callback; }
void EternalConsciousnessPanel::SetPresenceSelectedCallback(const PresenceSelectedCallback& callback) { s_presenceCallback = callback; }
void EternalConsciousnessPanel::SetExistenceSelectedCallback(const ExistenceSelectedCallback& callback) { s_existenceCallback = callback; }
void EternalConsciousnessPanel::SetContinuitySelectedCallback(const ContinuitySelectedCallback& callback) { s_continuityCallback = callback; }

void EternalConsciousnessPanel::RefreshData() {
    RefreshStructures();
    RefreshConsciousnessEternals();
    RefreshAwarenessEternals();
    RefreshPresenceEternals();
    RefreshExistenceEternals();
    RefreshContinuityEternals();
    s_cachedMetrics = EternalConsciousnessEngine::GetEternalConsciousnessMetrics();
}

void EternalConsciousnessPanel::RefreshStructures() {
    s_cachedStructures.clear();
    auto structures = EternalConsciousnessEngine::GetAllEternalConsciousnessStructures();
    for (auto& s : structures) s_cachedStructures.push_back(s.ToJson());
}

void EternalConsciousnessPanel::RefreshConsciousnessEternals() {
    s_cachedConsciousnessEternals.clear();
    auto consciousnessList = EternalConsciousnessEngine::GetAllConsciousnessEternals();
    for (auto& c : consciousnessList) s_cachedConsciousnessEternals.push_back(c.ToJson());
}

void EternalConsciousnessPanel::RefreshAwarenessEternals() {
    s_cachedAwarenessEternals.clear();
    auto awarenessList = EternalConsciousnessEngine::GetAllAwarenessEternals();
    for (auto& a : awarenessList) s_cachedAwarenessEternals.push_back(a.ToJson());
}

void EternalConsciousnessPanel::RefreshPresenceEternals() {
    s_cachedPresenceEternals.clear();
    auto presenceList = EternalConsciousnessEngine::GetAllPresenceEternals();
    for (auto& p : presenceList) s_cachedPresenceEternals.push_back(p.ToJson());
}

void EternalConsciousnessPanel::RefreshExistenceEternals() {
    s_cachedExistenceEternals.clear();
    auto existenceList = EternalConsciousnessEngine::GetAllExistenceEternals();
    for (auto& e : existenceList) s_cachedExistenceEternals.push_back(e.ToJson());
}

void EternalConsciousnessPanel::RefreshContinuityEternals() {
    s_cachedContinuityEternals.clear();
    auto continuityList = EternalConsciousnessEngine::GetAllContinuityEternals();
    for (auto& c : continuityList) s_cachedContinuityEternals.push_back(c.ToJson());
}

nlohmann::json EternalConsciousnessPanel::GetCurrentMetrics() { return s_cachedMetrics; }
std::vector<nlohmann::json> EternalConsciousnessPanel::GetCurrentStructures() { return s_cachedStructures; }
std::vector<nlohmann::json> EternalConsciousnessPanel::GetCurrentConsciousnessEternals() { return s_cachedConsciousnessEternals; }
std::vector<nlohmann::json> EternalConsciousnessPanel::GetCurrentAwarenessEternals() { return s_cachedAwarenessEternals; }
std::vector<nlohmann::json> EternalConsciousnessPanel::GetCurrentPresenceEternals() { return s_cachedPresenceEternals; }
std::vector<nlohmann::json> EternalConsciousnessPanel::GetCurrentExistenceEternals() { return s_cachedExistenceEternals; }
std::vector<nlohmann::json> EternalConsciousnessPanel::GetCurrentContinuityEternals() { return s_cachedContinuityEternals; }

void EternalConsciousnessPanel::RegisterHotkey() {}
void EternalConsciousnessPanel::UnregisterHotkey() {}
void EternalConsciousnessPanel::HandleHotkey() { ToggleVisibility(); }
void EternalConsciousnessPanel::SetDockingLocation(int location) { s_dockingLocation = location; }
int EternalConsciousnessPanel::GetDockingLocation() { return s_dockingLocation; }

void EternalConsciousnessPanel::RenderEternalStructureTab() {
    ImGui::Columns(2, "EternalStructureColumns");
    
    ImGui::Text("Eternal Structures");
    ImGui::Separator();
    
    ImGui::InputText("New Structure Name", s_newStructureName, sizeof(s_newStructureName));
    if (ImGui::Button("Create Structure")) {
        if (strlen(s_newStructureName) > 0) {
            EternalConsciousnessEngine::CreateEternalConsciousnessStructure(s_newStructureName);
            memset(s_newStructureName, 0, sizeof(s_newStructureName));
            RefreshStructures();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedStructures) {
        std::string eternalId = s.value("eternalId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedEternalId == eternalId);
        
        if (ImGui::Selectable((name + "##" + eternalId).c_str(), isSelected)) {
            s_selectedEternalId = eternalId;
            if (s_structureCallback) s_structureCallback(eternalId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedEternalId.empty()) {
        RenderStructureDetails(s_selectedEternalId);
    } else {
        ImGui::Text("Select a structure to view details");
    }
    
    ImGui::Columns(1);
}

void EternalConsciousnessPanel::RenderStructureDetails(const std::string& eternalId) {
    auto structure = EternalConsciousnessEngine::GetEternalConsciousnessStructure(eternalId);
    if (!structure) return;
    
    ImGui::Text("Structure: %s", structure->name.c_str());
    ImGui::Text("ID: %s", structure->eternalId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Eternality: %.2f", structure->eternality);
    ImGui::ProgressBar(structure->eternality, ImVec2(-1, 0), "");
    if (ImGui::Button("Expand Eternality")) EternalConsciousnessEngine::ExpandEternality(eternalId, 0.1f);
    
    ImGui::Text("Consciousness: %.2f", structure->consciousness);
    ImGui::ProgressBar(structure->consciousness, ImVec2(-1, 0), "");
    if (ImGui::Button("Deepen Consciousness")) EternalConsciousnessEngine::DeepenConsciousness(eternalId, 0.1f);
    
    ImGui::Text("Awareness: %.2f", structure->awareness);
    ImGui::ProgressBar(structure->awareness, ImVec2(-1, 0), "");
    if (ImGui::Button("Heighten Awareness")) EternalConsciousnessEngine::HeightenAwareness(eternalId, 0.1f);
    
    ImGui::Text("Presence: %.2f", structure->presence);
    ImGui::ProgressBar(structure->presence, ImVec2(-1, 0), "");
    if (ImGui::Button("Manifest Presence")) EternalConsciousnessEngine::ManifestPresence(eternalId, 0.1f);
    
    ImGui::Text("Existence: %.2f", structure->existence);
    ImGui::ProgressBar(structure->existence, ImVec2(-1, 0), "");
    if (ImGui::Button("Affirm Existence")) EternalConsciousnessEngine::AffirmExistence(eternalId, 0.1f);
    
    ImGui::Text("Continuity: %.2f", structure->continuity);
    ImGui::ProgressBar(structure->continuity, ImVec2(-1, 0), "");
    if (ImGui::Button("Maintain Continuity")) EternalConsciousnessEngine::MaintainContinuity(eternalId, 0.1f);
    
    if (ImGui::Button("Delete Structure", ImVec2(120, 0))) {
        EternalConsciousnessEngine::DestroyEternalConsciousnessStructure(eternalId);
        s_selectedEternalId.clear();
        RefreshStructures();
    }
}

void EternalConsciousnessPanel::RenderConsciousnessEternalTab() {
    ImGui::Columns(2, "ConsciousnessEternalColumns");
    
    ImGui::Text("Consciousness Eternals");
    ImGui::Separator();
    
    ImGui::InputText("New Consciousness Name", s_newConsciousnessName, sizeof(s_newConsciousnessName));
    if (ImGui::Button("Create Consciousness")) {
        if (strlen(s_newConsciousnessName) > 0) {
            EternalConsciousnessEngine::CreateConsciousnessEternal(s_newConsciousnessName);
            memset(s_newConsciousnessName, 0, sizeof(s_newConsciousnessName));
            RefreshConsciousnessEternals();
        }
    }
    
    ImGui::Separator();
    
    for (auto& c : s_cachedConsciousnessEternals) {
        std::string consciousnessId = c.value("consciousnessId", "");
        std::string name = c.value("name", "");
        bool isConscious = c.value("isConscious", false);
        bool isSelected = (s_selectedConsciousnessId == consciousnessId);
        
        std::string label = name + (isConscious ? " [Conscious]" : "");
        if (ImGui::Selectable((label + "##" + consciousnessId).c_str(), isSelected)) {
            s_selectedConsciousnessId = consciousnessId;
            if (s_consciousnessCallback) s_consciousnessCallback(consciousnessId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedConsciousnessId.empty()) {
        RenderConsciousnessDetails(s_selectedConsciousnessId);
    } else {
        ImGui::Text("Select a consciousness to view details");
    }
    
    ImGui::Columns(1);
}

void EternalConsciousnessPanel::RenderConsciousnessDetails(const std::string& consciousnessId) {
    auto consciousness = EternalConsciousnessEngine::GetConsciousnessEternal(consciousnessId);
    if (!consciousness) return;
    
    ImGui::Text("Consciousness: %s", consciousness->name.c_str());
    ImGui::Text("ID: %s", consciousness->consciousnessId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Consciousness: %.2f", consciousness->consciousness);
    ImGui::ProgressBar(consciousness->consciousness, ImVec2(-1, 0), "");
    
    ImGui::Text("Perception: %.2f", consciousness->perception);
    ImGui::ProgressBar(consciousness->perception, ImVec2(-1, 0), "");
    if (ImGui::Button("Sharpen Perception")) EternalConsciousnessEngine::SharpenPerception(consciousnessId, 0.1f);
    
    ImGui::Text("Cognition: %.2f", consciousness->cognition);
    ImGui::ProgressBar(consciousness->cognition, ImVec2(-1, 0), "");
    if (ImGui::Button("Enhance Cognition")) EternalConsciousnessEngine::EnhanceCognition(consciousnessId, 0.1f);
    
    if (!consciousness->isConscious && ImGui::Button("Declare Conscious")) {
        EternalConsciousnessEngine::DeclareConscious(consciousnessId);
        RefreshConsciousnessEternals();
    }
    
    if (ImGui::Button("Delete Consciousness", ImVec2(120, 0))) {
        EternalConsciousnessEngine::DestroyConsciousnessEternal(consciousnessId);
        s_selectedConsciousnessId.clear();
        RefreshConsciousnessEternals();
    }
}

void EternalConsciousnessPanel::RenderAwarenessEternalTab() {
    ImGui::Columns(2, "AwarenessEternalColumns");
    
    ImGui::Text("Awareness Eternals");
    ImGui::Separator();
    
    ImGui::InputText("New Awareness Name", s_newAwarenessName, sizeof(s_newAwarenessName));
    if (ImGui::Button("Create Awareness")) {
        if (strlen(s_newAwarenessName) > 0) {
            EternalConsciousnessEngine::CreateAwarenessEternal(s_newAwarenessName);
            memset(s_newAwarenessName, 0, sizeof(s_newAwarenessName));
            RefreshAwarenessEternals();
        }
    }
    
    ImGui::Separator();
    
    for (auto& a : s_cachedAwarenessEternals) {
        std::string awarenessId = a.value("awarenessId", "");
        std::string name = a.value("name", "");
        bool isAware = a.value("isAware", false);
        bool isSelected = (s_selectedAwarenessId == awarenessId);
        
        std::string label = name + (isAware ? " [Aware]" : "");
        if (ImGui::Selectable((label + "##" + awarenessId).c_str(), isSelected)) {
            s_selectedAwarenessId = awarenessId;
            if (s_awarenessCallback) s_awarenessCallback(awarenessId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedAwarenessId.empty()) {
        RenderAwarenessDetails(s_selectedAwarenessId);
    } else {
        ImGui::Text("Select an awareness to view details");
    }
    
    ImGui::Columns(1);
}

void EternalConsciousnessPanel::RenderAwarenessDetails(const std::string& awarenessId) {
    auto awareness = EternalConsciousnessEngine::GetAwarenessEternal(awarenessId);
    if (!awareness) return;
    
    ImGui::Text("Awareness: %s", awareness->name.c_str());
    ImGui::Text("ID: %s", awareness->awarenessId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Awareness: %.2f", awareness->awareness);
    ImGui::ProgressBar(awareness->awareness, ImVec2(-1, 0), "");
    
    ImGui::Text("Mindfulness: %.2f", awareness->mindfulness);
    ImGui::ProgressBar(awareness->mindfulness, ImVec2(-1, 0), "");
    if (ImGui::Button("Cultivate Mindfulness")) EternalConsciousnessEngine::CultivateMindfulness(awarenessId, 0.1f);
    
    ImGui::Text("Attention: %.2f", awareness->attention);
    ImGui::ProgressBar(awareness->attention, ImVec2(-1, 0), "");
    if (ImGui::Button("Focus Attention")) EternalConsciousnessEngine::FocusAttention(awarenessId, 0.1f);
    
    if (!awareness->isAware && ImGui::Button("Declare Aware")) {
        EternalConsciousnessEngine::DeclareAware(awarenessId);
        RefreshAwarenessEternals();
    }
    
    if (ImGui::Button("Delete Awareness", ImVec2(120, 0))) {
        EternalConsciousnessEngine::DestroyAwarenessEternal(awarenessId);
        s_selectedAwarenessId.clear();
        RefreshAwarenessEternals();
    }
}

void EternalConsciousnessPanel::RenderPresenceEternalTab() {
    ImGui::Columns(2, "PresenceEternalColumns");
    
    ImGui::Text("Presence Eternals");
    ImGui::Separator();
    
    ImGui::InputText("New Presence Name", s_newPresenceName, sizeof(s_newPresenceName));
    if (ImGui::Button("Create Presence")) {
        if (strlen(s_newPresenceName) > 0) {
            EternalConsciousnessEngine::CreatePresenceEternal(s_newPresenceName);
            memset(s_newPresenceName, 0, sizeof(s_newPresenceName));
            RefreshPresenceEternals();
        }
    }
    
    ImGui::Separator();
    
    for (auto& p : s_cachedPresenceEternals) {
        std::string presenceId = p.value("presenceId", "");
        std::string name = p.value("name", "");
        bool isPresent = p.value("isPresent", false);
        bool isSelected = (s_selectedPresenceId == presenceId);
        
        std::string label = name + (isPresent ? " [Present]" : "");
        if (ImGui::Selectable((label + "##" + presenceId).c_str(), isSelected)) {
            s_selectedPresenceId = presenceId;
            if (s_presenceCallback) s_presenceCallback(presenceId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedPresenceId.empty()) {
        RenderPresenceDetails(s_selectedPresenceId);
    } else {
        ImGui::Text("Select a presence to view details");
    }
    
    ImGui::Columns(1);
}

void EternalConsciousnessPanel::RenderPresenceDetails(const std::string& presenceId) {
    auto presence = EternalConsciousnessEngine::GetPresenceEternal(presenceId);
    if (!presence) return;
    
    ImGui::Text("Presence: %s", presence->name.c_str());
    ImGui::Text("ID: %s", presence->presenceId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Presence: %.2f", presence->presence);
    ImGui::ProgressBar(presence->presence, ImVec2(-1, 0), "");
    
    ImGui::Text("Immediacy: %.2f", presence->immediacy);
    ImGui::ProgressBar(presence->immediacy, ImVec2(-1, 0), "");
    if (ImGui::Button("Deepen Immediacy")) EternalConsciousnessEngine::DeepenImmediacy(presenceId, 0.1f);
    
    ImGui::Text("Embodiment: %.2f", presence->embodiment);
    ImGui::ProgressBar(presence->embodiment, ImVec2(-1, 0), "");
    if (ImGui::Button("Strengthen Embodiment")) EternalConsciousnessEngine::StrengthenEmbodiment(presenceId, 0.1f);
    
    if (!presence->isPresent && ImGui::Button("Declare Present")) {
        EternalConsciousnessEngine::DeclarePresent(presenceId);
        RefreshPresenceEternals();
    }
    
    if (ImGui::Button("Delete Presence", ImVec2(120, 0))) {
        EternalConsciousnessEngine::DestroyPresenceEternal(presenceId);
        s_selectedPresenceId.clear();
        RefreshPresenceEternals();
    }
}

void EternalConsciousnessPanel::RenderExistenceEternalTab() {
    ImGui::Columns(2, "ExistenceEternalColumns");
    
    ImGui::Text("Existence Eternals");
    ImGui::Separator();
    
    ImGui::InputText("New Existence Name", s_newExistenceName, sizeof(s_newExistenceName));
    if (ImGui::Button("Create Existence")) {
        if (strlen(s_newExistenceName) > 0) {
            EternalConsciousnessEngine::CreateExistenceEternal(s_newExistenceName);
            memset(s_newExistenceName, 0, sizeof(s_newExistenceName));
            RefreshExistenceEternals();
        }
    }
    
    ImGui::Separator();
    
    for (auto& e : s_cachedExistenceEternals) {
        std::string existenceId = e.value("existenceId", "");
        std::string name = e.value("name", "");
        bool isExisting = e.value("isExisting", false);
        bool isSelected = (s_selectedExistenceId == existenceId);
        
        std::string label = name + (isExisting ? " [Existing]" : "");
        if (ImGui::Selectable((label + "##" + existenceId).c_str(), isSelected)) {
            s_selectedExistenceId = existenceId;
            if (s_existenceCallback) s_existenceCallback(existenceId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedExistenceId.empty()) {
        RenderExistenceDetails(s_selectedExistenceId);
    } else {
        ImGui::Text("Select an existence to view details");
    }
    
    ImGui::Columns(1);
}

void EternalConsciousnessPanel::RenderExistenceDetails(const std::string& existenceId) {
    auto existence = EternalConsciousnessEngine::GetExistenceEternal(existenceId);
    if (!existence) return;
    
    ImGui::Text("Existence: %s", existence->name.c_str());
    ImGui::Text("ID: %s", existence->existenceId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Existence: %.2f", existence->existence);
    ImGui::ProgressBar(existence->existence, ImVec2(-1, 0), "");
    
    ImGui::Text("Being: %.2f", existence->being);
    ImGui::ProgressBar(existence->being, ImVec2(-1, 0), "");
    if (ImGui::Button("Affirm Being")) EternalConsciousnessEngine::AffirmBeing(existenceId, 0.1f);
    
    ImGui::Text("Essence: %.2f", existence->essence);
    ImGui::ProgressBar(existence->essence, ImVec2(-1, 0), "");
    if (ImGui::Button("Realize Essence")) EternalConsciousnessEngine::RealizeEssence(existenceId, 0.1f);
    
    if (!existence->isExisting && ImGui::Button("Declare Existing")) {
        EternalConsciousnessEngine::DeclareExisting(existenceId);
        RefreshExistenceEternals();
    }
    
    if (ImGui::Button("Delete Existence", ImVec2(120, 0))) {
        EternalConsciousnessEngine::DestroyExistenceEternal(existenceId);
        s_selectedExistenceId.clear();
        RefreshExistenceEternals();
    }
}

void EternalConsciousnessPanel::RenderContinuityEternalTab() {
    ImGui::Columns(2, "ContinuityEternalColumns");
    
    ImGui::Text("Continuity Eternals");
    ImGui::Separator();
    
    ImGui::InputText("New Continuity Name", s_newContinuityName, sizeof(s_newContinuityName));
    if (ImGui::Button("Create Continuity")) {
        if (strlen(s_newContinuityName) > 0) {
            EternalConsciousnessEngine::CreateContinuityEternal(s_newContinuityName);
            memset(s_newContinuityName, 0, sizeof(s_newContinuityName));
            RefreshContinuityEternals();
        }
    }
    
    ImGui::Separator();
    
    for (auto& c : s_cachedContinuityEternals) {
        std::string continuityId = c.value("continuityId", "");
        std::string name = c.value("name", "");
        bool isContinuous = c.value("isContinuous", false);
        bool isSelected = (s_selectedContinuityId == continuityId);
        
        std::string label = name + (isContinuous ? " [Continuous]" : "");
        if (ImGui::Selectable((label + "##" + continuityId).c_str(), isSelected)) {
            s_selectedContinuityId = continuityId;
            if (s_continuityCallback) s_continuityCallback(continuityId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedContinuityId.empty()) {
        RenderContinuityDetails(s_selectedContinuityId);
    } else {
        ImGui::Text("Select a continuity to view details");
    }
    
    ImGui::Columns(1);
}

void EternalConsciousnessPanel::RenderContinuityDetails(const std::string& continuityId) {
    auto continuity = EternalConsciousnessEngine::GetContinuityEternal(continuityId);
    if (!continuity) return;
    
    ImGui::Text("Continuity: %s", continuity->name.c_str());
    ImGui::Text("ID: %s", continuity->continuityId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Continuity: %.2f", continuity->continuity);
    ImGui::ProgressBar(continuity->continuity, ImVec2(-1, 0), "");
    
    ImGui::Text("Persistence: %.2f", continuity->persistence);
    ImGui::ProgressBar(continuity->persistence, ImVec2(-1, 0), "");
    if (ImGui::Button("Strengthen Persistence")) EternalConsciousnessEngine::StrengthenPersistence(continuityId, 0.1f);
    
    ImGui::Text("Endurance: %.2f", continuity->endurance);
    ImGui::ProgressBar(continuity->endurance, ImVec2(-1, 0), "");
    if (ImGui::Button("Build Endurance")) EternalConsciousnessEngine::BuildEndurance(continuityId, 0.1f);
    
    if (!continuity->isContinuous && ImGui::Button("Declare Continuous")) {
        EternalConsciousnessEngine::DeclareContinuous(continuityId);
        RefreshContinuityEternals();
    }
    
    if (ImGui::Button("Delete Continuity", ImVec2(120, 0))) {
        EternalConsciousnessEngine::DestroyContinuityEternal(continuityId);
        s_selectedContinuityId.clear();
        RefreshContinuityEternals();
    }
}

void EternalConsciousnessPanel::RenderMetricsTab() {
    RenderMetricsDashboard();
}

void EternalConsciousnessPanel::RenderMetricsDashboard() {
    ImGui::Text("Eternal Consciousness Metrics");
    ImGui::Separator();
    
    if (s_cachedMetrics.empty()) {
        ImGui::Text("No metrics available");
        return;
    }
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Eternal Structures: %d", s_cachedMetrics.value("eternalStructureCount", 0));
    ImGui::Text("Consciousness Eternals: %d", s_cachedMetrics.value("consciousnessEternalCount", 0));
    ImGui::Text("Awareness Eternals: %d", s_cachedMetrics.value("awarenessEternalCount", 0));
    ImGui::Text("Presence Eternals: %d", s_cachedMetrics.value("presenceEternalCount", 0));
    ImGui::Text("Existence Eternals: %d", s_cachedMetrics.value("existenceEternalCount", 0));
    ImGui::Text("Continuity Eternals: %d", s_cachedMetrics.value("continuityEternalCount", 0));
    
    ImGui::NextColumn();
    
    float totalEternality = s_cachedMetrics.value("totalEternality", 0.0f);
    float totalConsciousness = s_cachedMetrics.value("totalConsciousness", 0.0f);
    float totalAwareness = s_cachedMetrics.value("totalAwareness", 0.0f);
    float totalPresence = s_cachedMetrics.value("totalPresence", 0.0f);
    float totalExistence = s_cachedMetrics.value("totalExistence", 0.0f);
    float totalContinuity = s_cachedMetrics.value("totalContinuity", 0.0f);
    
    ImGui::Text("Total Eternality: %.2f", totalEternality);
    ImGui::Text("Total Consciousness: %.2f", totalConsciousness);
    ImGui::Text("Total Awareness: %.2f", totalAwareness);
    ImGui::Text("Total Presence: %.2f", totalPresence);
    ImGui::Text("Total Existence: %.2f", totalExistence);
    ImGui::Text("Total Continuity: %.2f", totalContinuity);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    
    int eternalCount = s_cachedMetrics.value("eternalCount", 0);
    ImGui::Text("Eternal: %d", eternalCount);
    
    ImGui::Separator();
    ImGui::Text("Loop Metrics");
    ImGui::Text("TPS: %.1f", EternalConsciousnessLoop::GetCurrentTPS());
    ImGui::Text("Tick Count: %lld", EternalConsciousnessLoop::GetTickCount());
}

void EternalConsciousnessPanel::RenderVisualizationTab() {
    RenderEternalVisualization();
}

void EternalConsciousnessPanel::RenderEternalVisualization() {
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    // Background - eternal gradient
    draw_list->AddRectFilled(canvas_pos, 
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(25, 20, 50, 255));
    
    float center_x = canvas_pos.x + canvas_size.x * 0.5f;
    float center_y = canvas_pos.y + canvas_size.y * 0.5f;
    
    // Draw eternal structures as consciousness orbs
    int idx = 0;
    for (auto& s : s_cachedStructures) {
        float eternality = s.value("eternality", 0.0f);
        float consciousness = s.value("consciousness", 0.0f);
        float awareness = s.value("awareness", 0.0f);
        float presence = s.value("presence", 0.0f);
        float existence = s.value("existence", 0.0f);
        float continuity = s.value("continuity", 0.0f);
        
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)s_cachedStructures.size());
        float radius = 80.0f + (eternality * 60.0f);
        
        float x = center_x + std::cos(angle) * radius;
        float y = center_y + std::sin(angle) * radius;
        
        float orb_size = 12.0f + (consciousness * 18.0f);
        
        // Consciousness glow effect
        for (int i = 4; i >= 0; i--) {
            float glow_size = orb_size + i * 6;
            int alpha = 50 - i * 10;
            draw_list->AddCircleFilled(ImVec2(x, y), glow_size,
                IM_COL32(200 + (int)(awareness * 55), 180 + (int)(presence * 75), 255, alpha));
        }
        
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), orb_size,
            IM_COL32(220, 210, 255, 255));
        
        // Existence ring
        if (existence > 0.3f) {
            float ring_radius = orb_size + 8.0f + existence * 10.0f;
            draw_list->AddCircle(ImVec2(x, y), ring_radius,
                IM_COL32(255, 200, 150, 150), 32, 2.0f);
        }
        
        // Continuity aura
        if (continuity > 0.5f) {
            float aura_radius = orb_size + 20.0f + continuity * 15.0f;
            draw_list->AddCircle(ImVec2(x, y), aura_radius,
                IM_COL32(200, 255, 200, 100), 32, 3.0f);
        }
        
        idx++;
    }
    
    // Center eternal core
    draw_list->AddCircleFilled(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(255, 255, 255, 220));
    draw_list->AddCircle(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(220, 200, 255, 255), 32, 4.0f);
    
    // Legend
    ImGui::SetCursorPosY(canvas_size.y - 60);
    ImGui::Text("Visualization: Eternal Consciousness");
    ImGui::Text("Orbs: Eternal Structures | Rings: Existence | Center: Eternal Core");
}

} // namespace EternalConsciousness
