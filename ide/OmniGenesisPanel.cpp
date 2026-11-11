#include "OmniGenesisPanel.hpp"
#include "OmniGenesisEngine.hpp"
#include "OmniGenesisLoop.hpp"
#include <imgui.h>
#include <algorithm>
#include <chrono>

namespace OmniGenesis {

// Static member definitions
bool OmniGenesisPanel::s_initialized = false;
bool OmniGenesisPanel::s_visible = true;
OmniGenesisPanelTab OmniGenesisPanel::s_activeTab = OmniGenesisPanelTab::OmniStructure;
int OmniGenesisPanel::s_dockingLocation = 1; // Right side by default

std::string OmniGenesisPanel::s_selectedOmniId;
std::string OmniGenesisPanel::s_selectedGenesisId;
std::string OmniGenesisPanel::s_selectedCreationId;
std::string OmniGenesisPanel::s_selectedOriginId;
std::string OmniGenesisPanel::s_selectedSourceId;

OmniGenesisPanel::StructureSelectedCallback OmniGenesisPanel::s_structureCallback;
OmniGenesisPanel::GenesisSelectedCallback OmniGenesisPanel::s_genesisCallback;
OmniGenesisPanel::CreationSelectedCallback OmniGenesisPanel::s_creationCallback;
OmniGenesisPanel::OriginSelectedCallback OmniGenesisPanel::s_originCallback;
OmniGenesisPanel::SourceSelectedCallback OmniGenesisPanel::s_sourceCallback;

nlohmann::json OmniGenesisPanel::s_cachedMetrics;
std::vector<nlohmann::json> OmniGenesisPanel::s_cachedStructures;
std::vector<nlohmann::json> OmniGenesisPanel::s_cachedGenesisOmnis;
std::vector<nlohmann::json> OmniGenesisPanel::s_cachedCreationOmnis;
std::vector<nlohmann::json> OmniGenesisPanel::s_cachedOriginOmnis;
std::vector<nlohmann::json> OmniGenesisPanel::s_cachedSourceOmnis;
std::chrono::steady_clock::time_point OmniGenesisPanel::s_lastRefresh;

char OmniGenesisPanel::s_newStructureName[256] = {};
char OmniGenesisPanel::s_newGenesisName[256] = {};
char OmniGenesisPanel::s_newCreationName[256] = {};
char OmniGenesisPanel::s_newOriginName[256] = {};
char OmniGenesisPanel::s_newSourceName[256] = {};

void OmniGenesisPanel::Init() {
    if (s_initialized) return;
    
    // Register with loop for automatic refresh
    OmniGenesisLoop::RegisterUpdateCallback([](float) {
        auto now = std::chrono::steady_clock::now();
        if (now - s_lastRefresh > std::chrono::seconds(1)) {
            RefreshData();
            s_lastRefresh = now;
        }
    });
    
    s_initialized = true;
    RefreshData();
}

void OmniGenesisPanel::Shutdown() {
    if (!s_initialized) return;
    s_initialized = false;
}

bool OmniGenesisPanel::IsInitialized() {
    return s_initialized;
}

void OmniGenesisPanel::Render() {
    if (!s_visible) return;
    
    bool open = s_visible;
    Render(&open);
    s_visible = open;
}

void OmniGenesisPanel::Render(bool* p_open) {
    if (!p_open || !*p_open) return;
    
    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Omni Genesis Panel##OmniGenesis", p_open)) {
        // Tab bar
        if (ImGui::BeginTabBar("OmniGenesisTabs")) {
            if (ImGui::BeginTabItem("Omni Structure")) {
                s_activeTab = OmniGenesisPanelTab::OmniStructure;
                RenderOmniStructureTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Genesis Omni")) {
                s_activeTab = OmniGenesisPanelTab::GenesisOmni;
                RenderGenesisOmniTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Creation Omni")) {
                s_activeTab = OmniGenesisPanelTab::CreationOmni;
                RenderCreationOmniTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Origin Omni")) {
                s_activeTab = OmniGenesisPanelTab::OriginOmni;
                RenderOriginOmniTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Source Omni")) {
                s_activeTab = OmniGenesisPanelTab::SourceOmni;
                RenderSourceOmniTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Metrics")) {
                s_activeTab = OmniGenesisPanelTab::Metrics;
                RenderMetricsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Visualization")) {
                s_activeTab = OmniGenesisPanelTab::Visualization;
                RenderVisualizationTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
}

void OmniGenesisPanel::Show() {
    s_visible = true;
}

void OmniGenesisPanel::Hide() {
    s_visible = false;
}

void OmniGenesisPanel::ToggleVisibility() {
    s_visible = !s_visible;
}

bool OmniGenesisPanel::IsVisible() {
    return s_visible;
}

void OmniGenesisPanel::SetActiveTab(OmniGenesisPanelTab tab) {
    s_activeTab = tab;
}

OmniGenesisPanelTab OmniGenesisPanel::GetActiveTab() {
    return s_activeTab;
}

void OmniGenesisPanel::SetStructureSelectedCallback(const StructureSelectedCallback& callback) {
    s_structureCallback = callback;
}

void OmniGenesisPanel::SetGenesisSelectedCallback(const GenesisSelectedCallback& callback) {
    s_genesisCallback = callback;
}

void OmniGenesisPanel::SetCreationSelectedCallback(const CreationSelectedCallback& callback) {
    s_creationCallback = callback;
}

void OmniGenesisPanel::SetOriginSelectedCallback(const OriginSelectedCallback& callback) {
    s_originCallback = callback;
}

void OmniGenesisPanel::SetSourceSelectedCallback(const SourceSelectedCallback& callback) {
    s_sourceCallback = callback;
}

void OmniGenesisPanel::RefreshData() {
    RefreshStructures();
    RefreshGenesisOmnis();
    RefreshCreationOmnis();
    RefreshOriginOmnis();
    RefreshSourceOmnis();
    s_cachedMetrics = OmniGenesisEngine::GetOmniGenesisMetrics();
}

void OmniGenesisPanel::RefreshStructures() {
    s_cachedStructures.clear();
    auto structures = OmniGenesisEngine::GetAllOmniGenesisStructures();
    for (auto& s : structures) {
        s_cachedStructures.push_back(s.ToJson());
    }
}

void OmniGenesisPanel::RefreshGenesisOmnis() {
    s_cachedGenesisOmnis.clear();
    auto geneses = OmniGenesisEngine::GetAllGenesisOmnis();
    for (auto& g : geneses) {
        s_cachedGenesisOmnis.push_back(g.ToJson());
    }
}

void OmniGenesisPanel::RefreshCreationOmnis() {
    s_cachedCreationOmnis.clear();
    auto creations = OmniGenesisEngine::GetAllCreationOmnis();
    for (auto& c : creations) {
        s_cachedCreationOmnis.push_back(c.ToJson());
    }
}

void OmniGenesisPanel::RefreshOriginOmnis() {
    s_cachedOriginOmnis.clear();
    auto origins = OmniGenesisEngine::GetAllOriginOmnis();
    for (auto& o : origins) {
        s_cachedOriginOmnis.push_back(o.ToJson());
    }
}

void OmniGenesisPanel::RefreshSourceOmnis() {
    s_cachedSourceOmnis.clear();
    auto sources = OmniGenesisEngine::GetAllSourceOmnis();
    for (auto& s : sources) {
        s_cachedSourceOmnis.push_back(s.ToJson());
    }
}

nlohmann::json OmniGenesisPanel::GetCurrentMetrics() {
    return s_cachedMetrics;
}

std::vector<nlohmann::json> OmniGenesisPanel::GetCurrentStructures() {
    return s_cachedStructures;
}

std::vector<nlohmann::json> OmniGenesisPanel::GetCurrentGenesisOmnis() {
    return s_cachedGenesisOmnis;
}

std::vector<nlohmann::json> OmniGenesisPanel::GetCurrentCreationOmnis() {
    return s_cachedCreationOmnis;
}

std::vector<nlohmann::json> OmniGenesisPanel::GetCurrentOriginOmnis() {
    return s_cachedOriginOmnis;
}

std::vector<nlohmann::json> OmniGenesisPanel::GetCurrentSourceOmnis() {
    return s_cachedSourceOmnis;
}

void OmniGenesisPanel::RegisterHotkey() {
    // Hotkey registration would be handled by IDE framework
    // Ctrl+Shift+F102 for Omni Genesis Panel
}

void OmniGenesisPanel::UnregisterHotkey() {
    // Unregister hotkey
}

void OmniGenesisPanel::HandleHotkey() {
    ToggleVisibility();
}

void OmniGenesisPanel::SetDockingLocation(int location) {
    s_dockingLocation = location;
}

int OmniGenesisPanel::GetDockingLocation() {
    return s_dockingLocation;
}

// Tab renderers
void OmniGenesisPanel::RenderOmniStructureTab() {
    ImGui::Columns(2, "OmniStructureColumns");
    
    // Left column - List
    ImGui::Text("Omni Structures");
    ImGui::Separator();
    
    ImGui::InputText("New Structure Name", s_newStructureName, sizeof(s_newStructureName));
    if (ImGui::Button("Create Structure")) {
        if (strlen(s_newStructureName) > 0) {
            OmniGenesisEngine::CreateOmniGenesisStructure(s_newStructureName);
            memset(s_newStructureName, 0, sizeof(s_newStructureName));
            RefreshStructures();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedStructures) {
        std::string omniId = s.value("omniId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedOmniId == omniId);
        
        if (ImGui::Selectable((name + "##" + omniId).c_str(), isSelected)) {
            s_selectedOmniId = omniId;
            if (s_structureCallback) s_structureCallback(omniId);
        }
    }
    
    ImGui::NextColumn();
    
    // Right column - Details
    if (!s_selectedOmniId.empty()) {
        RenderStructureDetails(s_selectedOmniId);
    } else {
        ImGui::Text("Select a structure to view details");
    }
    
    ImGui::Columns(1);
}

void OmniGenesisPanel::RenderStructureDetails(const std::string& omniId) {
    auto structure = OmniGenesisEngine::GetOmniGenesisStructure(omniId);
    if (!structure) return;
    
    ImGui::Text("Structure: %s", structure->name.c_str());
    ImGui::Text("ID: %s", structure->omniId.c_str());
    ImGui::Separator();
    
    // Metrics
    ImGui::Text("Omniscience: %.2f", structure->omniscience);
    ImGui::ProgressBar(structure->omniscience, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Expand Omniscience")) {
        OmniGenesisEngine::ExpandOmniscience(omniId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Genesis: %.2f", structure->genesis);
    ImGui::ProgressBar(structure->genesis, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Catalyze Genesis")) {
        OmniGenesisEngine::CatalyzeGenesis(omniId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Creation: %.2f", structure->creation);
    ImGui::ProgressBar(structure->creation, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Manifest Creation")) {
        OmniGenesisEngine::ManifestCreation(omniId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Origin: %.2f", structure->origin);
    ImGui::ProgressBar(structure->origin, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Establish Origin")) {
        OmniGenesisEngine::EstablishOrigin(omniId, 0.1f);
    }
    ImGui::SameLine();
    
    ImGui::Text("Source: %.2f", structure->source);
    ImGui::ProgressBar(structure->source, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Tap Source")) {
        OmniGenesisEngine::TapSource(omniId, 0.1f);
    }
    
    if (ImGui::Button("Delete Structure", ImVec2(120, 0))) {
        OmniGenesisEngine::DestroyOmniGenesisStructure(omniId);
        s_selectedOmniId.clear();
        RefreshStructures();
    }
}

void OmniGenesisPanel::RenderGenesisOmniTab() {
    ImGui::Columns(2, "GenesisOmniColumns");
    
    ImGui::Text("Genesis Omnis");
    ImGui::Separator();
    
    ImGui::InputText("New Genesis Name", s_newGenesisName, sizeof(s_newGenesisName));
    if (ImGui::Button("Create Genesis")) {
        if (strlen(s_newGenesisName) > 0) {
            OmniGenesisEngine::CreateGenesisOmni(s_newGenesisName);
            memset(s_newGenesisName, 0, sizeof(s_newGenesisName));
            RefreshGenesisOmnis();
        }
    }
    
    ImGui::Separator();
    
    for (auto& g : s_cachedGenesisOmnis) {
        std::string genesisId = g.value("genesisId", "");
        std::string name = g.value("name", "");
        bool isBorn = g.value("isBorn", false);
        bool isSelected = (s_selectedGenesisId == genesisId);
        
        std::string label = name + (isBorn ? " [Born]" : "");
        if (ImGui::Selectable((label + "##" + genesisId).c_str(), isSelected)) {
            s_selectedGenesisId = genesisId;
            if (s_genesisCallback) s_genesisCallback(genesisId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedGenesisId.empty()) {
        RenderGenesisDetails(s_selectedGenesisId);
    } else {
        ImGui::Text("Select a genesis to view details");
    }
    
    ImGui::Columns(1);
}

void OmniGenesisPanel::RenderGenesisDetails(const std::string& genesisId) {
    auto genesis = OmniGenesisEngine::GetGenesisOmni(genesisId);
    if (!genesis) return;
    
    ImGui::Text("Genesis: %s", genesis->name.c_str());
    ImGui::Text("ID: %s", genesis->genesisId.c_str());
    ImGui::Text("Status: %s", genesis->isBorn ? "Born" : "Emerging");
    ImGui::Separator();
    
    ImGui::Text("Genesis: %.2f", genesis->genesis);
    ImGui::ProgressBar(genesis->genesis, ImVec2(-1, 0), "");
    
    ImGui::Text("Birth: %.2f", genesis->birth);
    ImGui::ProgressBar(genesis->birth, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Nurture Birth")) {
        OmniGenesisEngine::NurtureBirth(genesisId, 0.1f);
    }
    
    ImGui::Text("Emergence: %.2f", genesis->emergence);
    ImGui::ProgressBar(genesis->emergence, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Foster Emergence")) {
        OmniGenesisEngine::FosterEmergence(genesisId, 0.1f);
    }
    
    if (!genesis->isBorn && ImGui::Button("Declare Born")) {
        OmniGenesisEngine::DeclareBorn(genesisId);
        RefreshGenesisOmnis();
    }
    
    if (ImGui::Button("Delete Genesis", ImVec2(120, 0))) {
        OmniGenesisEngine::DestroyGenesisOmni(genesisId);
        s_selectedGenesisId.clear();
        RefreshGenesisOmnis();
    }
}

void OmniGenesisPanel::RenderCreationOmniTab() {
    ImGui::Columns(2, "CreationOmniColumns");
    
    ImGui::Text("Creation Omnis");
    ImGui::Separator();
    
    ImGui::InputText("New Creation Name", s_newCreationName, sizeof(s_newCreationName));
    if (ImGui::Button("Create Creation")) {
        if (strlen(s_newCreationName) > 0) {
            OmniGenesisEngine::CreateCreationOmni(s_newCreationName);
            memset(s_newCreationName, 0, sizeof(s_newCreationName));
            RefreshCreationOmnis();
        }
    }
    
    ImGui::Separator();
    
    for (auto& c : s_cachedCreationOmnis) {
        std::string creationId = c.value("creationId", "");
        std::string name = c.value("name", "");
        bool isSelected = (s_selectedCreationId == creationId);
        
        if (ImGui::Selectable((name + "##" + creationId).c_str(), isSelected)) {
            s_selectedCreationId = creationId;
            if (s_creationCallback) s_creationCallback(creationId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedCreationId.empty()) {
        RenderCreationDetails(s_selectedCreationId);
    } else {
        ImGui::Text("Select a creation to view details");
    }
    
    ImGui::Columns(1);
}

void OmniGenesisPanel::RenderCreationDetails(const std::string& creationId) {
    auto creation = OmniGenesisEngine::GetCreationOmni(creationId);
    if (!creation) return;
    
    ImGui::Text("Creation: %s", creation->name.c_str());
    ImGui::Text("ID: %s", creation->creationId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Creation: %.2f", creation->creation);
    ImGui::ProgressBar(creation->creation, ImVec2(-1, 0), "");
    
    ImGui::Text("Manifestation: %.2f", creation->manifestation);
    ImGui::ProgressBar(creation->manifestation, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Enable Manifestation")) {
        OmniGenesisEngine::EnableManifestation(creationId, 0.1f);
    }
    
    ImGui::Text("Formation: %.2f", creation->formation);
    ImGui::ProgressBar(creation->formation, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Guide Formation")) {
        OmniGenesisEngine::GuideFormation(creationId, 0.1f);
    }
    
    if (ImGui::Button("Delete Creation", ImVec2(120, 0))) {
        OmniGenesisEngine::DestroyCreationOmni(creationId);
        s_selectedCreationId.clear();
        RefreshCreationOmnis();
    }
}

void OmniGenesisPanel::RenderOriginOmniTab() {
    ImGui::Columns(2, "OriginOmniColumns");
    
    ImGui::Text("Origin Omnis");
    ImGui::Separator();
    
    ImGui::InputText("New Origin Name", s_newOriginName, sizeof(s_newOriginName));
    if (ImGui::Button("Create Origin")) {
        if (strlen(s_newOriginName) > 0) {
            OmniGenesisEngine::CreateOriginOmni(s_newOriginName);
            memset(s_newOriginName, 0, sizeof(s_newOriginName));
            RefreshOriginOmnis();
        }
    }
    
    ImGui::Separator();
    
    for (auto& o : s_cachedOriginOmnis) {
        std::string originId = o.value("originId", "");
        std::string name = o.value("name", "");
        bool isOriginated = o.value("isOriginated", false);
        bool isSelected = (s_selectedOriginId == originId);
        
        std::string label = name + (isOriginated ? " [Originated]" : "");
        if (ImGui::Selectable((label + "##" + originId).c_str(), isSelected)) {
            s_selectedOriginId = originId;
            if (s_originCallback) s_originCallback(originId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedOriginId.empty()) {
        RenderOriginDetails(s_selectedOriginId);
    } else {
        ImGui::Text("Select an origin to view details");
    }
    
    ImGui::Columns(1);
}

void OmniGenesisPanel::RenderOriginDetails(const std::string& originId) {
    auto origin = OmniGenesisEngine::GetOriginOmni(originId);
    if (!origin) return;
    
    ImGui::Text("Origin: %s", origin->name.c_str());
    ImGui::Text("ID: %s", origin->originId.c_str());
    ImGui::Text("Status: %s", origin->isOriginated ? "Originated" : "Beginning");
    ImGui::Separator();
    
    ImGui::Text("Origin: %.2f", origin->origin);
    ImGui::ProgressBar(origin->origin, ImVec2(-1, 0), "");
    
    ImGui::Text("Beginning: %.2f", origin->beginning);
    ImGui::ProgressBar(origin->beginning, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Mark Beginning")) {
        OmniGenesisEngine::MarkBeginning(originId, 0.1f);
    }
    
    ImGui::Text("Inception: %.2f", origin->inception);
    ImGui::ProgressBar(origin->inception, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Commence Inception")) {
        OmniGenesisEngine::CommenceInception(originId, 0.1f);
    }
    
    if (!origin->isOriginated && ImGui::Button("Declare Originated")) {
        OmniGenesisEngine::DeclareOriginated(originId);
        RefreshOriginOmnis();
    }
    
    if (ImGui::Button("Delete Origin", ImVec2(120, 0))) {
        OmniGenesisEngine::DestroyOriginOmni(originId);
        s_selectedOriginId.clear();
        RefreshOriginOmnis();
    }
}

void OmniGenesisPanel::RenderSourceOmniTab() {
    ImGui::Columns(2, "SourceOmniColumns");
    
    ImGui::Text("Source Omnis");
    ImGui::Separator();
    
    ImGui::InputText("New Source Name", s_newSourceName, sizeof(s_newSourceName));
    if (ImGui::Button("Create Source")) {
        if (strlen(s_newSourceName) > 0) {
            OmniGenesisEngine::CreateSourceOmni(s_newSourceName);
            memset(s_newSourceName, 0, sizeof(s_newSourceName));
            RefreshSourceOmnis();
        }
    }
    
    ImGui::Separator();
    
    for (auto& s : s_cachedSourceOmnis) {
        std::string sourceId = s.value("sourceId", "");
        std::string name = s.value("name", "");
        bool isSelected = (s_selectedSourceId == sourceId);
        
        if (ImGui::Selectable((name + "##" + sourceId).c_str(), isSelected)) {
            s_selectedSourceId = sourceId;
            if (s_sourceCallback) s_sourceCallback(sourceId);
        }
    }
    
    ImGui::NextColumn();
    
    if (!s_selectedSourceId.empty()) {
        RenderSourceDetails(s_selectedSourceId);
    } else {
        ImGui::Text("Select a source to view details");
    }
    
    ImGui::Columns(1);
}

void OmniGenesisPanel::RenderSourceDetails(const std::string& sourceId) {
    auto source = OmniGenesisEngine::GetSourceOmni(sourceId);
    if (!source) return;
    
    ImGui::Text("Source: %s", source->name.c_str());
    ImGui::Text("ID: %s", source->sourceId.c_str());
    ImGui::Separator();
    
    ImGui::Text("Source: %.2f", source->source);
    ImGui::ProgressBar(source->source, ImVec2(-1, 0), "");
    
    ImGui::Text("Fountain: %.2f", source->fountain);
    ImGui::ProgressBar(source->fountain, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Channel Fountain")) {
        OmniGenesisEngine::ChannelFountain(sourceId, 0.1f);
    }
    
    ImGui::Text("Wellspring: %.2f", source->wellspring);
    ImGui::ProgressBar(source->wellspring, ImVec2(-1, 0), "");
    
    if (ImGui::Button("Access Wellspring")) {
        OmniGenesisEngine::AccessWellspring(sourceId, 0.1f);
    }
    
    if (ImGui::Button("Delete Source", ImVec2(120, 0))) {
        OmniGenesisEngine::DestroySourceOmni(sourceId);
        s_selectedSourceId.clear();
        RefreshSourceOmnis();
    }
}

void OmniGenesisPanel::RenderMetricsTab() {
    RenderMetricsDashboard();
}

void OmniGenesisPanel::RenderMetricsDashboard() {
    ImGui::Text("Omni Genesis Metrics");
    ImGui::Separator();
    
    if (s_cachedMetrics.empty()) {
        ImGui::Text("No metrics available");
        return;
    }
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Omni Structures: %d", s_cachedMetrics.value("omniStructureCount", 0));
    ImGui::Text("Genesis Omnis: %d", s_cachedMetrics.value("genesisOmniCount", 0));
    ImGui::Text("Creation Omnis: %d", s_cachedMetrics.value("creationOmniCount", 0));
    ImGui::Text("Origin Omnis: %d", s_cachedMetrics.value("originOmniCount", 0));
    ImGui::Text("Source Omnis: %d", s_cachedMetrics.value("sourceOmniCount", 0));
    
    ImGui::NextColumn();
    
    float totalOmniscience = s_cachedMetrics.value("totalOmniscience", 0.0f);
    float totalGenesis = s_cachedMetrics.value("totalGenesis", 0.0f);
    float totalCreation = s_cachedMetrics.value("totalCreation", 0.0f);
    float totalOrigin = s_cachedMetrics.value("totalOrigin", 0.0f);
    float totalSource = s_cachedMetrics.value("totalSource", 0.0f);
    
    ImGui::Text("Total Omniscience: %.2f", totalOmniscience);
    ImGui::Text("Total Genesis: %.2f", totalGenesis);
    ImGui::Text("Total Creation: %.2f", totalCreation);
    ImGui::Text("Total Origin: %.2f", totalOrigin);
    ImGui::Text("Total Source: %.2f", totalSource);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    
    int bornCount = s_cachedMetrics.value("bornCount", 0);
    int originatedCount = s_cachedMetrics.value("originatedCount", 0);
    
    ImGui::Text("Born: %d", bornCount);
    ImGui::Text("Originated: %d", originatedCount);
    
    // Loop metrics
    ImGui::Separator();
    ImGui::Text("Loop Metrics");
    ImGui::Text("TPS: %.1f", OmniGenesisLoop::GetCurrentTPS());
    ImGui::Text("Tick Count: %lld", OmniGenesisLoop::GetTickCount());
}

void OmniGenesisPanel::RenderVisualizationTab() {
    RenderOmniVisualization();
}

void OmniGenesisPanel::RenderOmniVisualization() {
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    // Background
    draw_list->AddRectFilled(canvas_pos, 
        ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y),
        IM_COL32(10, 10, 25, 255));
    
    float center_x = canvas_pos.x + canvas_size.x * 0.5f;
    float center_y = canvas_pos.y + canvas_size.y * 0.5f;
    
    // Draw omni structures as cosmic orbs
    int idx = 0;
    for (auto& s : s_cachedStructures) {
        float omniscience = s.value("omniscience", 0.0f);
        float genesis = s.value("genesis", 0.0f);
        float creation = s.value("creation", 0.0f);
        float origin = s.value("origin", 0.0f);
        float source = s.value("source", 0.0f);
        
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)s_cachedStructures.size());
        float radius = 80.0f + (omniscience * 60.0f);
        
        float x = center_x + std::cos(angle) * radius;
        float y = center_y + std::sin(angle) * radius;
        
        float orb_size = 12.0f + (genesis * 18.0f);
        
        // Glow effect
        for (int i = 4; i >= 0; i--) {
            float glow_size = orb_size + i * 6;
            int alpha = 60 - i * 10;
            draw_list->AddCircleFilled(ImVec2(x, y), glow_size,
                IM_COL32(100 + (int)(creation * 155), 200 + (int)(origin * 55), 255, alpha));
        }
        
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), orb_size,
            IM_COL32(200 + (int)(source * 55), 220, 255, 255));
        
        // Genesis sparks
        if (genesis > 0.3f) {
            float spark_angle = angle + (idx % 2 == 0 ? 0.3f : -0.3f);
            float spark_x = x + std::cos(spark_angle) * (orb_size + 10);
            float spark_y = y + std::sin(spark_angle) * (orb_size + 10);
            draw_list->AddCircleFilled(ImVec2(spark_x, spark_y), 4.0f,
                IM_COL32(255, 255, 150, 200));
        }
        
        idx++;
    }
    
    // Center omni core
    draw_list->AddCircleFilled(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(255, 255, 255, 220));
    draw_list->AddCircle(ImVec2(center_x, center_y), 30.0f,
        IM_COL32(100, 200, 255, 255), 32, 4.0f);
    
    // Legend
    ImGui::SetCursorPosY(canvas_size.y - 60);
    ImGui::Text("Visualization: Omni Genesis");
    ImGui::Text("Orbs: Omni Structures | Sparks: Genesis Energy | Center: Omni Core");
}

} // namespace OmniGenesis
