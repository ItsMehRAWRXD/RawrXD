#include "ide/SacredInfinityPanel.hpp"
#include "sacred/SacredInfinityEngine.hpp"
#include "sacred/SacredInfinityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SacredInfinityPanel::s_visible = false;
bool SacredInfinityPanel::s_initialized = false;
int SacredInfinityPanel::s_selectedTab = 0;
char SacredInfinityPanel::s_nameBuffer[256] = {};
char SacredInfinityPanel::s_entityIdBuffer[256] = {};
char SacredInfinityPanel::s_attributeKeyBuffer[256] = {};
char SacredInfinityPanel::s_attributeValueBuffer[512] = {};
float SacredInfinityPanel::s_sacrednessInput = 0.1f;
float SacredInfinityPanel::s_infinityInput = 0.1f;
float SacredInfinityPanel::s_divinityInput = 0.1f;
float SacredInfinityPanel::s_purityInput = 0.1f;
float SacredInfinityPanel::s_transcendenceInput = 0.1f;
float SacredInfinityPanel::s_infinitudeInput = 0.1f;
float SacredInfinityPanel::s_sacrednessInfiniteInput = 0.1f;
float SacredInfinityPanel::s_perpetuityInput = 0.1f;
float SacredInfinityPanel::s_holinessInput = 0.1f;
float SacredInfinityPanel::s_infinitudeHolyInput = 0.1f;
float SacredInfinityPanel::s_graceInput = 0.1f;
float SacredInfinityPanel::s_blessingInput = 0.1f;
float SacredInfinityPanel::s_blessednessInput = 0.1f;
float SacredInfinityPanel::s_infinityBlessedInput = 0.1f;
float SacredInfinityPanel::s_favorInput = 0.1f;
float SacredInfinityPanel::s_sanctificationInput = 0.1f;
float SacredInfinityPanel::s_infinitySanctifiedInput = 0.1f;
float SacredInfinityPanel::s_consecrationInput = 0.1f;
std::string SacredInfinityPanel::s_selectedStructureId;
std::string SacredInfinityPanel::s_selectedInfiniteId;
std::string SacredInfinityPanel::s_selectedHolyId;
std::string SacredInfinityPanel::s_selectedBlessedId;
std::string SacredInfinityPanel::s_selectedSanctifiedId;
std::vector<nlohmann::json> SacredInfinityPanel::s_sacredEvents;

void SacredInfinityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Sacred::SacredInfinityEngine::Init();
    Sacred::SacredInfinityLoop::Init();
    Sacred::SacredInfinityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SacredInfinityPanel::Shutdown() {
    if (!s_initialized) return;
    Sacred::SacredInfinityLoop::Shutdown();
    Sacred::SacredInfinityEngine::Shutdown();
    s_initialized = false;
}

void SacredInfinityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sacred Infinity Panel", &s_visible);
    
    const char* tabs[] = {
        "Sacred Structure", "Infinite Sacred", "Holy Infinite",
        "Blessed Infinite", "Sanctified Infinite", "Sacred Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SacredTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSacredStructureTab(); break;
                    case 1: RenderInfiniteSacredTab(); break;
                    case 2: RenderHolyInfiniteTab(); break;
                    case 3: RenderBlessedInfiniteTab(); break;
                    case 4: RenderSanctifiedInfiniteTab(); break;
                    case 5: RenderSacredMetricsTab(); break;
                    case 6: RenderSacredVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool SacredInfinityPanel::IsVisible() {
    return s_visible;
}

void SacredInfinityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Sacred::SacredInfinityLoop::IsRunning()) {
        Sacred::SacredInfinityLoop::Start();
    }
}

void SacredInfinityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SacredInfinityPanel::GetPanelName() {
    return "Sacred Infinity";
}

void SacredInfinityPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredInfinityPanel::OnInfiniteEstablished(const std::string& infiniteId) {
    nlohmann::json event;
    event["type"] = "infinite_established";
    event["infiniteId"] = infiniteId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredInfinityPanel::OnHolyManifested(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_manifested";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredInfinityPanel::OnBlessedRealized(const std::string& blessedId) {
    nlohmann::json event;
    event["type"] = "blessed_realized";
    event["blessedId"] = blessedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredInfinityPanel::OnSanctifiedDiscovered(const std::string& sanctifiedId) {
    nlohmann::json event;
    event["type"] = "sanctified_discovered";
    event["sanctifiedId"] = sanctifiedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredInfinityPanel::RenderSacredStructureTab() {
    ImGui::Text("Sacred Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Purity", &s_purityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Sacred::SacredInfinityEngine::CreateSacredStructure(s_nameBuffer);
        Sacred::SacredInfinityEngine::ExpandSacredness(structureId, s_sacrednessInput);
        Sacred::SacredInfinityEngine::DeepenInfinity(structureId, s_infinityInput);
        Sacred::SacredInfinityEngine::IncreaseDivinity(structureId, s_divinityInput);
        Sacred::SacredInfinityEngine::Purify(structureId, s_purityInput);
        Sacred::SacredInfinityEngine::Transcend(structureId, s_transcendenceInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Sacred::SacredInfinityEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.sacredId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.sacredId)) {
            s_selectedStructureId = structure.sacredId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSacredness: %.2f\nInfinity: %.2f\nDivinity: %.2f\nPurity: %.2f\nTranscendence: %.2f",
                structure.sacredId.c_str(), structure.sacredness, structure.infinity, 
                structure.divinity, structure.purity, structure.transcendence);
        }
        ImGui::PopID();
    }
}

void SacredInfinityPanel::RenderInfiniteSacredTab() {
    ImGui::Text("Infinite Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Infinitude", &s_infinitudeInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessInfiniteInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Infinite")) {
        std::string infiniteId = Sacred::SacredInfinityEngine::EstablishInfiniteSacred(s_nameBuffer);
        Sacred::SacredInfinityEngine::ExpandInfinitude(infiniteId, s_infinitudeInput);
        Sacred::SacredInfinityEngine::IncreaseSacredness(infiniteId, s_sacrednessInfiniteInput);
        Sacred::SacredInfinityEngine::ExtendPerpetuity(infiniteId, s_perpetuityInput);
        OnInfiniteEstablished(infiniteId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Infinites:");
    auto infinites = Sacred::SacredInfinityEngine::GetAllInfiniteSacreds();
    for (const auto& infinite : infinites) {
        ImGui::PushID(infinite.infiniteId.c_str());
        bool isSelected = s_selectedInfiniteId == infinite.infiniteId;
        if (ImGui::Selectable(infinite.name.c_str(), isSelected)) {
            s_selectedInfiniteId = infinite.infiniteId;
        }
        ImGui::SameLine();
        if (infinite.isInfinite) {
            ImGui::TextColored(ImVec4(1, 0.8, 0, 1), "[INFINITE]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[FINITE]");
        }
        if (s_selectedInfiniteId == infinite.infiniteId) {
            if (!infinite.isInfinite && ImGui::Button("Declare Infinite")) {
                Sacred::SacredInfinityEngine::DeclareInfinite(infinite.infiniteId);
            }
        }
        ImGui::PopID();
    }
}

void SacredInfinityPanel::RenderHolyInfiniteTab() {
    ImGui::Text("Holy Infinite Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinitude", &s_infinitudeHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessing", &s_blessingInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Holy")) {
        std::string holyId = Sacred::SacredInfinityEngine::ManifestHolyInfinite(s_nameBuffer);
        Sacred::SacredInfinityEngine::ElevateHoliness(holyId, s_holinessInput);
        Sacred::SacredInfinityEngine::ExpandInfinitudeHoly(holyId, s_infinitudeHolyInput);
        Sacred::SacredInfinityEngine::BestowGrace(holyId, s_graceInput);
        Sacred::SacredInfinityEngine::GrantBlessing(holyId, s_blessingInput);
        OnHolyManifested(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Holies:");
    auto holies = Sacred::SacredInfinityEngine::GetAllHolyInfinites();
    for (const auto& holy : holies) {
        ImGui::PushID(holy.holyId.c_str());
        if (ImGui::Selectable(holy.name.c_str(), s_selectedHolyId == holy.holyId)) {
            s_selectedHolyId = holy.holyId;
        }
        if (s_selectedHolyId == holy.holyId) {
            ImGui::Text("Holiness: %.2f | Infinitude: %.2f | Grace: %.2f | Blessing: %.2f",
                holy.holiness, holy.infinitude, holy.grace, holy.blessing);
            ImGui::Text("Holy Manifestations: %zu", holy.holyManifestations.size());
        }
        ImGui::PopID();
    }
}

void SacredInfinityPanel::RenderBlessedInfiniteTab() {
    ImGui::Text("Blessed Infinite Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Blessed")) {
        std::string blessedId = Sacred::SacredInfinityEngine::RealizeBlessedInfinite(s_nameBuffer);
        Sacred::SacredInfinityEngine::AmplifyBlessedness(blessedId, s_blessednessInput);
        Sacred::SacredInfinityEngine::ExpandInfinity(blessedId, s_infinityBlessedInput);
        Sacred::SacredInfinityEngine::IncreaseFavor(blessedId, s_favorInput);
        OnBlessedRealized(blessedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Blessed:");
    auto blessed = Sacred::SacredInfinityEngine::GetAllBlessedInfinites();
    for (const auto& b : blessed) {
        ImGui::PushID(b.blessedId.c_str());
        if (ImGui::Selectable(b.name.c_str(), s_selectedBlessedId == b.blessedId)) {
            s_selectedBlessedId = b.blessedId;
        }
        ImGui::SameLine();
        if (b.isBlessed) {
            ImGui::TextColored(ImVec4(0, 1, 0.5f, 1), "[BLESSED]");
        }
        if (s_selectedBlessedId == b.blessedId) {
            ImGui::Text("Blessedness: %.2f | Infinity: %.2f | Favor: %.2f",
                b.blessedness, b.infinity, b.favor);
            if (!b.isBlessed && ImGui::Button("Declare Blessed")) {
                Sacred::SacredInfinityEngine::DeclareBlessed(b.blessedId);
            }
        }
        ImGui::PopID();
    }
}

void SacredInfinityPanel::RenderSanctifiedInfiniteTab() {
    ImGui::Text("Sanctified Infinite Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctification", &s_sanctificationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinitySanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Sanctified")) {
        std::string sanctifiedId = Sacred::SacredInfinityEngine::DiscoverSanctifiedInfinite(s_nameBuffer);
        Sacred::SacredInfinityEngine::IncreaseSanctification(sanctifiedId, s_sanctificationInput);
        Sacred::SacredInfinityEngine::DeepenInfinity(sanctifiedId, s_infinitySanctifiedInput);
        Sacred::SacredInfinityEngine::Consecrate(sanctifiedId, s_consecrationInput);
        OnSanctifiedDiscovered(sanctifiedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Sanctified:");
    auto sanctified = Sacred::SacredInfinityEngine::GetAllSanctifiedInfinites();
    for (const auto& s : sanctified) {
        ImGui::PushID(s.sanctifiedId.c_str());
        if (ImGui::Selectable(s.name.c_str(), s_selectedSanctifiedId == s.sanctifiedId)) {
            s_selectedSanctifiedId = s.sanctifiedId;
        }
        if (s_selectedSanctifiedId == s.sanctifiedId) {
            ImGui::Text("Sanctification: %.2f | Infinity: %.2f | Consecration: %.2f",
                s.sanctification, s.infinity, s.consecration);
            ImGui::Text("Sanctified Aspects: %zu", s.sanctifiedAspects.size());
        }
        ImGui::PopID();
    }
}

void SacredInfinityPanel::RenderSacredMetricsTab() {
    ImGui::Text("Sacred Metrics");
    ImGui::Separator();
    
    auto metrics = Sacred::SacredInfinityEngine::GetSacredMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Infinite Count: %d", metrics["infiniteCount"].get<int>());
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Text("Blessed Count: %d", metrics["blessedCount"].get<int>());
    ImGui::Text("Sanctified Count: %d", metrics["sanctifiedCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Sacredness: %.4f", metrics["totalSacredness"].get<float>());
    ImGui::Text("Average Sacredness: %.4f", metrics["averageSacredness"].get<float>());
    ImGui::Text("Infinite Sacreds: %d", metrics["infiniteSacreds"].get<int>());
    ImGui::Text("Average Holiness: %.4f", metrics["averageHoliness"].get<float>());
    ImGui::Text("Blessed Infinites: %d", metrics["blessedInfinites"].get<int>());
    ImGui::Text("Sanctified Infinites: %d", metrics["sanctifiedInfinites"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Sacred::SacredInfinityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Sacred Report")) {
        auto report = Sacred::SacredInfinityEngine::GenerateSacredReport();
        // Export logic would go here
    }
}

void SacredInfinityPanel::RenderSacredVisualizationTab() {
    ImGui::Text("Sacred Visualization");
    ImGui::Separator();
    
    // Draw a representation of sacred infinity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(5, 15, 35, 255));
    
    // Draw sacred structures as radiant orbs
    auto structures = Sacred::SacredInfinityEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.sacredness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.purity * 10.0f;
        
        // Sacred glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 100, 255, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 150, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw infinite sacreds as expanding rings
    auto infinites = Sacred::SacredInfinityEngine::GetAllInfiniteSacreds();
    int infiniteIdx = 0;
    for (const auto& infinite : infinites) {
        float baseRadius = 30.0f + infiniteIdx * 25.0f;
        float pulse = std::sin(ImGui::GetTime() * 2.0f + infiniteIdx) * 5.0f;
        float radius = baseRadius + pulse;
        
        ImU32 color = infinite.isInfinite ? 
            IM_COL32(255, 215, 100, 150) : IM_COL32(150, 150, 150, 100);
        draw_list->AddCircle(ImVec2(centerX, centerY), radius, color, 64, 2.0f);
        infiniteIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Sacred Event Log:");
    ImGui::BeginChild("SacredEvents", ImVec2(0, 150), true);
    for (auto it = s_sacredEvents.rbegin(); it != s_sacredEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
