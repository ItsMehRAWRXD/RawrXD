#include "ide/SacredEternityPanel.hpp"
#include "sacred/SacredEternityEngine.hpp"
#include "sacred/SacredEternityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SacredEternityPanel::s_visible = false;
bool SacredEternityPanel::s_initialized = false;
int SacredEternityPanel::s_selectedTab = 0;
char SacredEternityPanel::s_nameBuffer[256] = {};
char SacredEternityPanel::s_entityIdBuffer[256] = {};
char SacredEternityPanel::s_attributeKeyBuffer[256] = {};
char SacredEternityPanel::s_attributeValueBuffer[512] = {};
float SacredEternityPanel::s_sacrednessInput = 0.1f;
float SacredEternityPanel::s_eternityInput = 0.1f;
float SacredEternityPanel::s_reverenceInput = 0.1f;
float SacredEternityPanel::s_sanctityInput = 0.1f;
float SacredEternityPanel::s_devotionInput = 0.1f;
float SacredEternityPanel::s_eternitySacredInput = 0.1f;
float SacredEternityPanel::s_sacrednessEternityInput = 0.1f;
float SacredEternityPanel::s_perpetuityInput = 0.1f;
float SacredEternityPanel::s_timelessnessInput = 0.1f;
float SacredEternityPanel::s_reverentSacredInput = 0.1f;
float SacredEternityPanel::s_sacrednessReverentInput = 0.1f;
float SacredEternityPanel::s_aweInput = 0.1f;
float SacredEternityPanel::s_venerationInput = 0.1f;
float SacredEternityPanel::s_sanctitySacredInput = 0.1f;
float SacredEternityPanel::s_sacrednessSanctityInput = 0.1f;
float SacredEternityPanel::s_holinessInput = 0.1f;
float SacredEternityPanel::s_blessednessInput = 0.1f;
float SacredEternityPanel::s_devotedSacredInput = 0.1f;
float SacredEternityPanel::s_sacrednessDevotedInput = 0.1f;
float SacredEternityPanel::s_dedicationInput = 0.1f;
float SacredEternityPanel::s_commitmentInput = 0.1f;
std::string SacredEternityPanel::s_selectedSacredId;
std::string SacredEternityPanel::s_selectedEternityId;
std::string SacredEternityPanel::s_selectedReverentId;
std::string SacredEternityPanel::s_selectedSanctityId;
std::string SacredEternityPanel::s_selectedDevotedId;
std::vector<nlohmann::json> SacredEternityPanel::s_sacredEvents;

void SacredEternityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    SacredEternity::SacredEternityEngine::Init();
    SacredEternity::SacredEternityLoop::Init();
    SacredEternity::SacredEternityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SacredEternityPanel::Shutdown() {
    if (!s_initialized) return;
    SacredEternity::SacredEternityLoop::Shutdown();
    SacredEternity::SacredEternityEngine::Shutdown();
    s_initialized = false;
}

void SacredEternityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sacred Eternity Panel", &s_visible);
    
    const char* tabs[] = {
        "Sacred Structure", "Eternity Sacred", "Reverent Sacred",
        "Sanctity Sacred", "Devoted Sacred", "Sacred Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SacredTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSacredStructureTab(); break;
                    case 1: RenderEternitySacredTab(); break;
                    case 2: RenderReverentSacredTab(); break;
                    case 3: RenderSanctitySacredTab(); break;
                    case 4: RenderDevotedSacredTab(); break;
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

bool SacredEternityPanel::IsVisible() {
    return s_visible;
}

void SacredEternityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !SacredEternity::SacredEternityLoop::IsRunning()) {
        SacredEternity::SacredEternityLoop::Start();
    }
}

void SacredEternityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SacredEternityPanel::GetPanelName() {
    return "Sacred Eternity";
}

void SacredEternityPanel::OnSacredStructureCreated(const std::string& sacredId) {
    nlohmann::json event;
    event["type"] = "sacred_structure_created";
    event["sacredId"] = sacredId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredEternityPanel::OnEternityEstablished(const std::string& eternityId) {
    nlohmann::json event;
    event["type"] = "eternity_established";
    event["eternityId"] = eternityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredEternityPanel::OnReverentManifested(const std::string& reverentId) {
    nlohmann::json event;
    event["type"] = "reverent_manifested";
    event["reverentId"] = reverentId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredEternityPanel::OnSanctityRealized(const std::string& sanctityId) {
    nlohmann::json event;
    event["type"] = "sanctity_realized";
    event["sanctityId"] = sanctityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredEternityPanel::OnDevotedDiscovered(const std::string& devotedId) {
    nlohmann::json event;
    event["type"] = "devoted_discovered";
    event["devotedId"] = devotedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredEternityPanel::RenderSacredStructureTab() {
    ImGui::Text("Sacred Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternity", &s_eternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Reverence", &s_reverenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctity", &s_sanctityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Devotion", &s_devotionInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string sacredId = SacredEternity::SacredEternityEngine::CreateSacredEternityStructure(s_nameBuffer);
        SacredEternity::SacredEternityEngine::ExpandSacredness(sacredId, s_sacrednessInput);
        SacredEternity::SacredEternityEngine::ExpandEternity(sacredId, s_eternityInput);
        SacredEternity::SacredEternityEngine::DeepenReverence(sacredId, s_reverenceInput);
        SacredEternity::SacredEternityEngine::ElevateSanctity(sacredId, s_sanctityInput);
        SacredEternity::SacredEternityEngine::StrengthenDevotion(sacredId, s_devotionInput);
        OnSacredStructureCreated(sacredId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = SacredEternity::SacredEternityEngine::GetAllSacredEternityStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.sacredId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedSacredId == structure.sacredId)) {
            s_selectedSacredId = structure.sacredId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSacredness: %.2f\nEternity: %.2f\nReverence: %.2f\nSanctity: %.2f\nDevotion: %.2f",
                structure.sacredId.c_str(), structure.sacredness, structure.eternity, 
                structure.reverence, structure.sanctity, structure.devotion);
        }
        ImGui::PopID();
    }
}

void SacredEternityPanel::RenderEternitySacredTab() {
    ImGui::Text("Eternity Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternity", &s_eternitySacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessEternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Timelessness", &s_timelessnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Eternity")) {
        std::string eternityId = SacredEternity::SacredEternityEngine::CreateEternitySacred(s_nameBuffer);
        SacredEternity::SacredEternityEngine::PerpetuateEternity(eternityId, s_eternitySacredInput);
        SacredEternity::SacredEternityEngine::ExpandTimelessness(eternityId, s_timelessnessInput);
        OnEternityEstablished(eternityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Eternities:");
    auto eternities = SacredEternity::SacredEternityEngine::GetAllEternitySacreds();
    for (const auto& eternity : eternities) {
        ImGui::PushID(eternity.eternityId.c_str());
        bool isSelected = s_selectedEternityId == eternity.eternityId;
        if (ImGui::Selectable(eternity.name.c_str(), isSelected)) {
            s_selectedEternityId = eternity.eternityId;
        }
        ImGui::SameLine();
        if (eternity.isEternal) {
            ImGui::TextColored(ImVec4(0.8f, 1, 0.5f, 1), "[ETERNAL]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[TEMPORAL]");
        }
        if (s_selectedEternityId == eternity.eternityId) {
            if (!eternity.isEternal && ImGui::Button("Declare Eternal")) {
                SacredEternity::SacredEternityEngine::DeclareEternal(eternity.eternityId);
            }
        }
        ImGui::PopID();
    }
}

void SacredEternityPanel::RenderReverentSacredTab() {
    ImGui::Text("Reverent Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Reverence", &s_reverentSacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessReverentInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Awe", &s_aweInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Veneration", &s_venerationInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Reverent")) {
        std::string reverentId = SacredEternity::SacredEternityEngine::CreateReverentSacred(s_nameBuffer);
        SacredEternity::SacredEternityEngine::InspireAwe(reverentId, s_aweInput);
        SacredEternity::SacredEternityEngine::DeepenVeneration(reverentId, s_venerationInput);
        OnReverentManifested(reverentId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Reverents:");
    auto reverents = SacredEternity::SacredEternityEngine::GetAllReverentSacreds();
    for (const auto& reverent : reverents) {
        ImGui::PushID(reverent.reverentId.c_str());
        if (ImGui::Selectable(reverent.name.c_str(), s_selectedReverentId == reverent.reverentId)) {
            s_selectedReverentId = reverent.reverentId;
        }
        if (s_selectedReverentId == reverent.reverentId) {
            ImGui::Text("Reverence: %.2f | Sacredness: %.2f | Awe: %.2f | Veneration: %.2f",
                reverent.reverence, reverent.sacredness, reverent.awe, reverent.veneration);
        }
        ImGui::PopID();
    }
}

void SacredEternityPanel::RenderSanctitySacredTab() {
    ImGui::Text("Sanctity Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctity", &s_sanctitySacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessSanctityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Sanctity")) {
        std::string sanctityId = SacredEternity::SacredEternityEngine::CreateSanctitySacred(s_nameBuffer);
        SacredEternity::SacredEternityEngine::ElevateHoliness(sanctityId, s_holinessInput);
        SacredEternity::SacredEternityEngine::AmplifyBlessedness(sanctityId, s_blessednessInput);
        OnSanctityRealized(sanctityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Sanctities:");
    auto sanctities = SacredEternity::SacredEternityEngine::GetAllSanctitySacreds();
    for (const auto& sanctity : sanctities) {
        ImGui::PushID(sanctity.sanctityId.c_str());
        if (ImGui::Selectable(sanctity.name.c_str(), s_selectedSanctityId == sanctity.sanctityId)) {
            s_selectedSanctityId = sanctity.sanctityId;
        }
        if (s_selectedSanctityId == sanctity.sanctityId) {
            ImGui::Text("Sanctity: %.2f | Sacredness: %.2f | Holiness: %.2f | Blessedness: %.2f",
                sanctity.sanctity, sanctity.sacredness, sanctity.holiness, sanctity.blessedness);
        }
        ImGui::PopID();
    }
}

void SacredEternityPanel::RenderDevotedSacredTab() {
    ImGui::Text("Devoted Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Devotion", &s_devotedSacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessDevotedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dedication", &s_dedicationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Commitment", &s_commitmentInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Devoted")) {
        std::string devotedId = SacredEternity::SacredEternityEngine::CreateDevotedSacred(s_nameBuffer);
        SacredEternity::SacredEternityEngine::IntensifyDedication(devotedId, s_dedicationInput);
        SacredEternity::SacredEternityEngine::StrengthenCommitment(devotedId, s_commitmentInput);
        OnDevotedDiscovered(devotedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Devoteds:");
    auto devoteds = SacredEternity::SacredEternityEngine::GetAllDevotedSacreds();
    for (const auto& devoted : devoteds) {
        ImGui::PushID(devoted.devotedId.c_str());
        if (ImGui::Selectable(devoted.name.c_str(), s_selectedDevotedId == devoted.devotedId)) {
            s_selectedDevotedId = devoted.devotedId;
        }
        if (s_selectedDevotedId == devoted.devotedId) {
            ImGui::Text("Devotion: %.2f | Sacredness: %.2f | Dedication: %.2f | Commitment: %.2f",
                devoted.devotion, devoted.sacredness, devoted.dedication, devoted.commitment);
        }
        ImGui::PopID();
    }
}

void SacredEternityPanel::RenderSacredMetricsTab() {
    ImGui::Text("Sacred Eternity Metrics");
    ImGui::Separator();
    
    auto metrics = SacredEternity::SacredEternityEngine::GetSacredEternityMetrics();
    
    ImGui::Text("Sacred Count: %d", metrics["sacredCount"].get<int>());
    ImGui::Text("Eternity Count: %d", metrics["eternityCount"].get<int>());
    ImGui::Text("Reverent Count: %d", metrics["reverentCount"].get<int>());
    ImGui::Text("Sanctity Count: %d", metrics["sanctityCount"].get<int>());
    ImGui::Text("Devoted Count: %d", metrics["devotedCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Sacredness: %.4f", metrics["totalSacredness"].get<float>());
    ImGui::Text("Average Sacredness: %.4f", metrics["averageSacredness"].get<float>());
    ImGui::Text("Sacred Sacreds: %d", metrics["sacredSacreds"].get<int>());
    ImGui::Text("Total Eternity: %.4f", metrics["totalEternity"].get<float>());
    ImGui::Text("Eternal Sacreds: %d", metrics["eternalSacreds"].get<int>());
    ImGui::Text("Reverent Sacreds: %d", metrics["reverentSacreds"].get<int>());
    ImGui::Text("Sanctified Sacreds: %d", metrics["sanctifiedSacreds"].get<int>());
    ImGui::Text("Devoted Sacreds: %d", metrics["devotedSacreds"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", SacredEternity::SacredEternityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Sacred Report")) {
        auto report = SacredEternity::SacredEternityEngine::GenerateSacredEternityReport();
        // Export logic would go here
    }
}

void SacredEternityPanel::RenderSacredVisualizationTab() {
    ImGui::Text("Sacred Eternity Visualization");
    ImGui::Separator();
    
    // Draw a representation of sacred eternity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(35, 30, 45, 255));
    
    // Draw sacred structures as radiant orbs
    auto structures = SacredEternity::SacredEternityEngine::GetAllSacredEternityStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.sacredness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.reverence * 10.0f;
        
        // Sacred glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(255, 200, 150, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 220, 180, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw eternity sacreds as eternal rays
    auto eternities = SacredEternity::SacredEternityEngine::GetAllEternitySacreds();
    int eternityIdx = 0;
    for (const auto& eternity : eternities) {
        float angle = (eternityIdx * 2.0f * 3.14159f) / std::max(1, (int)eternities.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + eternity.timelessness * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = eternity.isEternal ? 
            IM_COL32(200, 255, 150, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + eternity.eternity * 3.0f);
        eternityIdx++;
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
