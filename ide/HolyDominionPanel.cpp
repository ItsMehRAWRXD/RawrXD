#include "ide/HolyDominionPanel.hpp"
#include "holy/HolyDominionEngine.hpp"
#include "holy/HolyDominionLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool HolyDominionPanel::s_visible = false;
bool HolyDominionPanel::s_initialized = false;
int HolyDominionPanel::s_selectedTab = 0;
char HolyDominionPanel::s_nameBuffer[256] = {};
char HolyDominionPanel::s_entityIdBuffer[256] = {};
char HolyDominionPanel::s_attributeKeyBuffer[256] = {};
char HolyDominionPanel::s_attributeValueBuffer[512] = {};
float HolyDominionPanel::s_holinessInput = 0.1f;
float HolyDominionPanel::s_dominionInput = 0.1f;
float HolyDominionPanel::s_authorityInput = 0.1f;
float HolyDominionPanel::s_graceInput = 0.1f;
float HolyDominionPanel::s_blessingInput = 0.1f;
float HolyDominionPanel::s_dominionHolyInput = 0.1f;
float HolyDominionPanel::s_holinessDominionInput = 0.1f;
float HolyDominionPanel::s_sovereigntyInput = 0.1f;
float HolyDominionPanel::s_sacrednessInput = 0.1f;
float HolyDominionPanel::s_dominionSacredInput = 0.1f;
float HolyDominionPanel::s_reverenceInput = 0.1f;
float HolyDominionPanel::s_sanctityInput = 0.1f;
float HolyDominionPanel::s_blessednessInput = 0.1f;
float HolyDominionPanel::s_dominionBlessedInput = 0.1f;
float HolyDominionPanel::s_favorInput = 0.1f;
float HolyDominionPanel::s_sanctificationInput = 0.1f;
float HolyDominionPanel::s_dominionSanctifiedInput = 0.1f;
float HolyDominionPanel::s_consecrationInput = 0.1f;
std::string HolyDominionPanel::s_selectedStructureId;
std::string HolyDominionPanel::s_selectedDominionId;
std::string HolyDominionPanel::s_selectedSacredId;
std::string HolyDominionPanel::s_selectedBlessedId;
std::string HolyDominionPanel::s_selectedSanctifiedId;
std::vector<nlohmann::json> HolyDominionPanel::s_holyEvents;

void HolyDominionPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Holy::HolyDominionEngine::Init();
    Holy::HolyDominionLoop::Init();
    Holy::HolyDominionLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void HolyDominionPanel::Shutdown() {
    if (!s_initialized) return;
    Holy::HolyDominionLoop::Shutdown();
    Holy::HolyDominionEngine::Shutdown();
    s_initialized = false;
}

void HolyDominionPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Holy Dominion Panel", &s_visible);
    
    const char* tabs[] = {
        "Holy Structure", "Dominion Holy", "Sacred Dominion",
        "Blessed Dominion", "Sanctified Dominion", "Holy Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("HolyTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderHolyStructureTab(); break;
                    case 1: RenderDominionHolyTab(); break;
                    case 2: RenderSacredDominionTab(); break;
                    case 3: RenderBlessedDominionTab(); break;
                    case 4: RenderSanctifiedDominionTab(); break;
                    case 5: RenderHolyMetricsTab(); break;
                    case 6: RenderHolyVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool HolyDominionPanel::IsVisible() {
    return s_visible;
}

void HolyDominionPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Holy::HolyDominionLoop::IsRunning()) {
        Holy::HolyDominionLoop::Start();
    }
}

void HolyDominionPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* HolyDominionPanel::GetPanelName() {
    return "Holy Dominion";
}

void HolyDominionPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyDominionPanel::OnDominionEstablished(const std::string& dominionId) {
    nlohmann::json event;
    event["type"] = "dominion_established";
    event["dominionId"] = dominionId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyDominionPanel::OnSacredManifested(const std::string& sacredId) {
    nlohmann::json event;
    event["type"] = "sacred_manifested";
    event["sacredId"] = sacredId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyDominionPanel::OnBlessedRealized(const std::string& blessedId) {
    nlohmann::json event;
    event["type"] = "blessed_realized";
    event["blessedId"] = blessedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyDominionPanel::OnSanctifiedDiscovered(const std::string& sanctifiedId) {
    nlohmann::json event;
    event["type"] = "sanctified_discovered";
    event["sanctifiedId"] = sanctifiedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyDominionPanel::RenderHolyStructureTab() {
    ImGui::Text("Holy Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessing", &s_blessingInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Holy::HolyDominionEngine::CreateHolyStructure(s_nameBuffer);
        Holy::HolyDominionEngine::ExpandHoliness(structureId, s_holinessInput);
        Holy::HolyDominionEngine::ExtendDominion(structureId, s_dominionInput);
        Holy::HolyDominionEngine::IncreaseAuthority(structureId, s_authorityInput);
        Holy::HolyDominionEngine::BestowGrace(structureId, s_graceInput);
        Holy::HolyDominionEngine::GrantBlessing(structureId, s_blessingInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Holy::HolyDominionEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.holyId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.holyId)) {
            s_selectedStructureId = structure.holyId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nHoliness: %.2f\nDominion: %.2f\nAuthority: %.2f\nGrace: %.2f\nBlessing: %.2f",
                structure.holyId.c_str(), structure.holiness, structure.dominion, 
                structure.authority, structure.grace, structure.blessing);
        }
        ImGui::PopID();
    }
}

void HolyDominionPanel::RenderDominionHolyTab() {
    ImGui::Text("Dominion Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Dominion", &s_dominionHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessDominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sovereignty", &s_sovereigntyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Dominion")) {
        std::string dominionId = Holy::HolyDominionEngine::EstablishDominionHoly(s_nameBuffer);
        Holy::HolyDominionEngine::ExpandDominion(dominionId, s_dominionHolyInput);
        Holy::HolyDominionEngine::IncreaseHoliness(dominionId, s_holinessDominionInput);
        Holy::HolyDominionEngine::AssertSovereignty(dominionId, s_sovereigntyInput);
        OnDominionEstablished(dominionId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Dominions:");
    auto dominions = Holy::HolyDominionEngine::GetAllDominionHolies();
    for (const auto& dominion : dominions) {
        ImGui::PushID(dominion.dominionId.c_str());
        bool isSelected = s_selectedDominionId == dominion.dominionId;
        if (ImGui::Selectable(dominion.name.c_str(), isSelected)) {
            s_selectedDominionId = dominion.dominionId;
        }
        ImGui::SameLine();
        if (dominion.isDominion) {
            ImGui::TextColored(ImVec4(1, 0.8, 0, 1), "[DOMINION]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[STANDARD]");
        }
        if (s_selectedDominionId == dominion.dominionId) {
            if (!dominion.isDominion && ImGui::Button("Declare Dominion")) {
                Holy::HolyDominionEngine::DeclareDominion(dominion.dominionId);
            }
        }
        ImGui::PopID();
    }
}

void HolyDominionPanel::RenderSacredDominionTab() {
    ImGui::Text("Sacred Dominion Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionSacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Reverence", &s_reverenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctity", &s_sanctityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Sacred")) {
        std::string sacredId = Holy::HolyDominionEngine::ManifestSacredDominion(s_nameBuffer);
        Holy::HolyDominionEngine::ElevateSacredness(sacredId, s_sacrednessInput);
        Holy::HolyDominionEngine::ExpandDominionSacred(sacredId, s_dominionSacredInput);
        Holy::HolyDominionEngine::DeepenReverence(sacredId, s_reverenceInput);
        Holy::HolyDominionEngine::IncreaseSanctity(sacredId, s_sanctityInput);
        OnSacredManifested(sacredId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Sacred:");
    auto sacreds = Holy::HolyDominionEngine::GetAllSacredDominions();
    for (const auto& sacred : sacreds) {
        ImGui::PushID(sacred.sacredId.c_str());
        if (ImGui::Selectable(sacred.name.c_str(), s_selectedSacredId == sacred.sacredId)) {
            s_selectedSacredId = sacred.sacredId;
        }
        if (s_selectedSacredId == sacred.sacredId) {
            ImGui::Text("Sacredness: %.2f | Dominion: %.2f | Reverence: %.2f | Sanctity: %.2f",
                sacred.sacredness, sacred.dominion, sacred.reverence, sacred.sanctity);
            ImGui::Text("Sacred Manifestations: %zu", sacred.sacredManifestations.size());
        }
        ImGui::PopID();
    }
}

void HolyDominionPanel::RenderBlessedDominionTab() {
    ImGui::Text("Blessed Dominion Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Blessed")) {
        std::string blessedId = Holy::HolyDominionEngine::RealizeBlessedDominion(s_nameBuffer);
        Holy::HolyDominionEngine::AmplifyBlessedness(blessedId, s_blessednessInput);
        Holy::HolyDominionEngine::ExtendDominion(blessedId, s_dominionBlessedInput);
        Holy::HolyDominionEngine::IncreaseFavor(blessedId, s_favorInput);
        OnBlessedRealized(blessedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Blessed:");
    auto blessed = Holy::HolyDominionEngine::GetAllBlessedDominions();
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
            ImGui::Text("Blessedness: %.2f | Dominion: %.2f | Favor: %.2f",
                b.blessedness, b.dominion, b.favor);
            if (!b.isBlessed && ImGui::Button("Declare Blessed")) {
                Holy::HolyDominionEngine::DeclareBlessed(b.blessedId);
            }
        }
        ImGui::PopID();
    }
}

void HolyDominionPanel::RenderSanctifiedDominionTab() {
    ImGui::Text("Sanctified Dominion Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctification", &s_sanctificationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Sanctified")) {
        std::string sanctifiedId = Holy::HolyDominionEngine::DiscoverSanctifiedDominion(s_nameBuffer);
        Holy::HolyDominionEngine::IncreaseSanctification(sanctifiedId, s_sanctificationInput);
        Holy::HolyDominionEngine::DeepenDominion(sanctifiedId, s_dominionSanctifiedInput);
        Holy::HolyDominionEngine::Consecrate(sanctifiedId, s_consecrationInput);
        OnSanctifiedDiscovered(sanctifiedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Sanctified:");
    auto sanctified = Holy::HolyDominionEngine::GetAllSanctifiedDominions();
    for (const auto& s : sanctified) {
        ImGui::PushID(s.sanctifiedId.c_str());
        if (ImGui::Selectable(s.name.c_str(), s_selectedSanctifiedId == s.sanctifiedId)) {
            s_selectedSanctifiedId = s.sanctifiedId;
        }
        if (s_selectedSanctifiedId == s.sanctifiedId) {
            ImGui::Text("Sanctification: %.2f | Dominion: %.2f | Consecration: %.2f",
                s.sanctification, s.dominion, s.consecration);
            ImGui::Text("Sanctified Aspects: %zu", s.sanctifiedAspects.size());
        }
        ImGui::PopID();
    }
}

void HolyDominionPanel::RenderHolyMetricsTab() {
    ImGui::Text("Holy Metrics");
    ImGui::Separator();
    
    auto metrics = Holy::HolyDominionEngine::GetHolyMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Dominion Count: %d", metrics["dominionCount"].get<int>());
    ImGui::Text("Sacred Count: %d", metrics["sacredCount"].get<int>());
    ImGui::Text("Blessed Count: %d", metrics["blessedCount"].get<int>());
    ImGui::Text("Sanctified Count: %d", metrics["sanctifiedCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Holiness: %.4f", metrics["totalHoliness"].get<float>());
    ImGui::Text("Average Holiness: %.4f", metrics["averageHoliness"].get<float>());
    ImGui::Text("Dominion Holies: %d", metrics["dominionHolies"].get<int>());
    ImGui::Text("Average Sacredness: %.4f", metrics["averageSacredness"].get<float>());
    ImGui::Text("Blessed Dominions: %d", metrics["blessedDominions"].get<int>());
    ImGui::Text("Sanctified Dominions: %d", metrics["sanctifiedDominions"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Holy::HolyDominionLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Holy Report")) {
        auto report = Holy::HolyDominionEngine::GenerateHolyReport();
        // Export logic would go here
    }
}

void HolyDominionPanel::RenderHolyVisualizationTab() {
    ImGui::Text("Holy Dominion Visualization");
    ImGui::Separator();
    
    // Draw a representation of holy dominion
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(15, 10, 30, 255));
    
    // Draw holy structures as radiant orbs
    auto structures = Holy::HolyDominionEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.holiness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.authority * 10.0f;
        
        // Holy glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(255, 200, 100, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 220, 150, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw dominion holies as authority rays
    auto dominions = Holy::HolyDominionEngine::GetAllDominionHolies();
    int dominionIdx = 0;
    for (const auto& dominion : dominions) {
        float angle = (dominionIdx * 2.0f * 3.14159f) / std::max(1, (int)dominions.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + dominion.sovereignty * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = dominion.isDominion ? 
            IM_COL32(255, 180, 80, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + dominion.dominion * 3.0f);
        dominionIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Holy Event Log:");
    ImGui::BeginChild("HolyEvents", ImVec2(0, 150), true);
    for (auto it = s_holyEvents.rbegin(); it != s_holyEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
