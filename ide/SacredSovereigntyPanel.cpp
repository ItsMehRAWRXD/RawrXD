#include "ide/SacredSovereigntyPanel.hpp"
#include "sacred/SacredSovereigntyEngine.hpp"
#include "sacred/SacredSovereigntyLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SacredSovereigntyPanel::s_visible = false;
bool SacredSovereigntyPanel::s_initialized = false;
int SacredSovereigntyPanel::s_selectedTab = 0;
char SacredSovereigntyPanel::s_nameBuffer[256] = {};
char SacredSovereigntyPanel::s_entityIdBuffer[256] = {};
char SacredSovereigntyPanel::s_attributeKeyBuffer[256] = {};
char SacredSovereigntyPanel::s_attributeValueBuffer[512] = {};
float SacredSovereigntyPanel::s_sacrednessInput = 0.1f;
float SacredSovereigntyPanel::s_sovereigntyInput = 0.1f;
float SacredSovereigntyPanel::s_authorityInput = 0.1f;
float SacredSovereigntyPanel::s_dominionInput = 0.1f;
float SacredSovereigntyPanel::s_supremacyInput = 0.1f;
float SacredSovereigntyPanel::s_sovereigntySacredInput = 0.1f;
float SacredSovereigntyPanel::s_sacrednessSovereigntyInput = 0.1f;
float SacredSovereigntyPanel::s_ruleInput = 0.1f;
float SacredSovereigntyPanel::s_reignInput = 0.1f;
float SacredSovereigntyPanel::s_authoritySacredInput = 0.1f;
float SacredSovereigntyPanel::s_sacrednessAuthorityInput = 0.1f;
float SacredSovereigntyPanel::s_commandInput = 0.1f;
float SacredSovereigntyPanel::s_controlInput = 0.1f;
float SacredSovereigntyPanel::s_dominionSacredInput = 0.1f;
float SacredSovereigntyPanel::s_sacrednessDominionInput = 0.1f;
float SacredSovereigntyPanel::s_territoryInput = 0.1f;
float SacredSovereigntyPanel::s_realmInput = 0.1f;
float SacredSovereigntyPanel::s_supremacySacredInput = 0.1f;
float SacredSovereigntyPanel::s_sacrednessSupremacyInput = 0.1f;
float SacredSovereigntyPanel::s_dominanceInput = 0.1f;
float SacredSovereigntyPanel::s_preeminenceInput = 0.1f;
std::string SacredSovereigntyPanel::s_selectedSacredId;
std::string SacredSovereigntyPanel::s_selectedSovereigntyId;
std::string SacredSovereigntyPanel::s_selectedAuthorityId;
std::string SacredSovereigntyPanel::s_selectedDominionId;
std::string SacredSovereigntyPanel::s_selectedSupremacyId;
std::vector<nlohmann::json> SacredSovereigntyPanel::s_sacredEvents;

void SacredSovereigntyPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    SacredSovereignty::SacredSovereigntyEngine::Init();
    SacredSovereignty::SacredSovereigntyLoop::Init();
    SacredSovereignty::SacredSovereigntyLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SacredSovereigntyPanel::Shutdown() {
    if (!s_initialized) return;
    SacredSovereignty::SacredSovereigntyLoop::Shutdown();
    SacredSovereignty::SacredSovereigntyEngine::Shutdown();
    s_initialized = false;
}

void SacredSovereigntyPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sacred Sovereignty Panel", &s_visible);
    
    const char* tabs[] = {
        "Sacred Structure", "Sovereignty Sacred", "Authority Sacred",
        "Dominion Sacred", "Supremacy Sacred", "Sacred Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SacredTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSacredStructureTab(); break;
                    case 1: RenderSovereigntySacredTab(); break;
                    case 2: RenderAuthoritySacredTab(); break;
                    case 3: RenderDominionSacredTab(); break;
                    case 4: RenderSupremacySacredTab(); break;
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

bool SacredSovereigntyPanel::IsVisible() {
    return s_visible;
}

void SacredSovereigntyPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !SacredSovereignty::SacredSovereigntyLoop::IsRunning()) {
        SacredSovereignty::SacredSovereigntyLoop::Start();
    }
}

void SacredSovereigntyPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SacredSovereigntyPanel::GetPanelName() {
    return "Sacred Sovereignty";
}

void SacredSovereigntyPanel::OnSacredStructureCreated(const std::string& sacredId) {
    nlohmann::json event;
    event["type"] = "sacred_structure_created";
    event["sacredId"] = sacredId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredSovereigntyPanel::OnSovereigntyEstablished(const std::string& sovereigntyId) {
    nlohmann::json event;
    event["type"] = "sovereignty_established";
    event["sovereigntyId"] = sovereigntyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredSovereigntyPanel::OnAuthorityAsserted(const std::string& authorityId) {
    nlohmann::json event;
    event["type"] = "authority_asserted";
    event["authorityId"] = authorityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredSovereigntyPanel::OnDominionExtended(const std::string& dominionId) {
    nlohmann::json event;
    event["type"] = "dominion_extended";
    event["dominionId"] = dominionId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredSovereigntyPanel::OnSupremacyAchieved(const std::string& supremacyId) {
    nlohmann::json event;
    event["type"] = "supremacy_achieved";
    event["supremacyId"] = supremacyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredSovereigntyPanel::RenderSacredStructureTab() {
    ImGui::Text("Sacred Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sovereignty", &s_sovereigntyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Supremacy", &s_supremacyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string sacredId = SacredSovereignty::SacredSovereigntyEngine::CreateSacredSovereigntyStructure(s_nameBuffer);
        SacredSovereignty::SacredSovereigntyEngine::ElevateSacredness(sacredId, s_sacrednessInput);
        SacredSovereignty::SacredSovereigntyEngine::ExpandSovereignty(sacredId, s_sovereigntyInput);
        SacredSovereignty::SacredSovereigntyEngine::AssertAuthority(sacredId, s_authorityInput);
        SacredSovereignty::SacredSovereigntyEngine::ExtendDominion(sacredId, s_dominionInput);
        SacredSovereignty::SacredSovereigntyEngine::AchieveSupremacy(sacredId, s_supremacyInput);
        OnSacredStructureCreated(sacredId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = SacredSovereignty::SacredSovereigntyEngine::GetAllSacredSovereigntyStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.sacredId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedSacredId == structure.sacredId)) {
            s_selectedSacredId = structure.sacredId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSacredness: %.2f\nSovereignty: %.2f\nAuthority: %.2f\nDominion: %.2f\nSupremacy: %.2f",
                structure.sacredId.c_str(), structure.sacredness, structure.sovereignty, 
                structure.authority, structure.dominion, structure.supremacy);
        }
        ImGui::PopID();
    }
}

void SacredSovereigntyPanel::RenderSovereigntySacredTab() {
    ImGui::Text("Sovereignty Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sovereignty", &s_sovereigntySacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessSovereigntyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Rule", &s_ruleInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Reign", &s_reignInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Sovereignty")) {
        std::string sovereigntyId = SacredSovereignty::SacredSovereigntyEngine::CreateSovereigntySacred(s_nameBuffer);
        SacredSovereignty::SacredSovereigntyEngine::EstablishRule(sovereigntyId, s_ruleInput);
        SacredSovereignty::SacredSovereigntyEngine::ExtendReign(sovereigntyId, s_reignInput);
        OnSovereigntyEstablished(sovereigntyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Sovereignties:");
    auto sovereignties = SacredSovereignty::SacredSovereigntyEngine::GetAllSovereigntySacreds();
    for (const auto& sovereignty : sovereignties) {
        ImGui::PushID(sovereignty.sovereigntyId.c_str());
        bool isSelected = s_selectedSovereigntyId == sovereignty.sovereigntyId;
        if (ImGui::Selectable(sovereignty.name.c_str(), isSelected)) {
            s_selectedSovereigntyId = sovereignty.sovereigntyId;
        }
        ImGui::SameLine();
        if (sovereignty.isAbsolute) {
            ImGui::TextColored(ImVec4(0.8f, 0.5f, 1.0f, 1), "[ABSOLUTE]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[LIMITED]");
        }
        if (s_selectedSovereigntyId == sovereignty.sovereigntyId) {
            if (!sovereignty.isAbsolute && ImGui::Button("Declare Absolute")) {
                SacredSovereignty::SacredSovereigntyEngine::DeclareAbsolute(sovereignty.sovereigntyId);
            }
        }
        ImGui::PopID();
    }
}

void SacredSovereigntyPanel::RenderAuthoritySacredTab() {
    ImGui::Text("Authority Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Authority", &s_authoritySacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessAuthorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Command", &s_commandInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Control", &s_controlInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Assert Authority")) {
        std::string authorityId = SacredSovereignty::SacredSovereigntyEngine::CreateAuthoritySacred(s_nameBuffer);
        SacredSovereignty::SacredSovereigntyEngine::IssueCommand(authorityId, s_commandInput);
        SacredSovereignty::SacredSovereigntyEngine::SeizeControl(authorityId, s_controlInput);
        OnAuthorityAsserted(authorityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Asserted Authorities:");
    auto authorities = SacredSovereignty::SacredSovereigntyEngine::GetAllAuthoritySacreds();
    for (const auto& authority : authorities) {
        ImGui::PushID(authority.authorityId.c_str());
        if (ImGui::Selectable(authority.name.c_str(), s_selectedAuthorityId == authority.authorityId)) {
            s_selectedAuthorityId = authority.authorityId;
        }
        if (s_selectedAuthorityId == authority.authorityId) {
            ImGui::Text("Authority: %.2f | Sacredness: %.2f | Command: %.2f | Control: %.2f",
                authority.authority, authority.sacredness, authority.command, authority.control);
        }
        ImGui::PopID();
    }
}

void SacredSovereigntyPanel::RenderDominionSacredTab() {
    ImGui::Text("Dominion Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Dominion", &s_dominionSacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessDominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Territory", &s_territoryInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Realm", &s_realmInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Extend Dominion")) {
        std::string dominionId = SacredSovereignty::SacredSovereigntyEngine::CreateDominionSacred(s_nameBuffer);
        SacredSovereignty::SacredSovereigntyEngine::ExpandTerritory(dominionId, s_territoryInput);
        SacredSovereignty::SacredSovereigntyEngine::ClaimRealm(dominionId, s_realmInput);
        OnDominionExtended(dominionId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Extended Dominions:");
    auto dominions = SacredSovereignty::SacredSovereigntyEngine::GetAllDominionSacreds();
    for (const auto& dominion : dominions) {
        ImGui::PushID(dominion.dominionId.c_str());
        bool isSelected = s_selectedDominionId == dominion.dominionId;
        if (ImGui::Selectable(dominion.name.c_str(), isSelected)) {
            s_selectedDominionId = dominion.dominionId;
        }
        ImGui::SameLine();
        if (dominion.isVast) {
            ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "[VAST]");
        }
        if (s_selectedDominionId == dominion.dominionId) {
            ImGui::Text("Dominion: %.2f | Sacredness: %.2f | Territory: %.2f | Realm: %.2f",
                dominion.dominion, dominion.sacredness, dominion.territory, dominion.realm);
            if (!dominion.isVast && ImGui::Button("Declare Vast")) {
                SacredSovereignty::SacredSovereigntyEngine::DeclareVast(dominion.dominionId);
            }
        }
        ImGui::PopID();
    }
}

void SacredSovereigntyPanel::RenderSupremacySacredTab() {
    ImGui::Text("Supremacy Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Supremacy", &s_supremacySacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessSupremacyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominance", &s_dominanceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Preeminence", &s_preeminenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Achieve Supremacy")) {
        std::string supremacyId = SacredSovereignty::SacredSovereigntyEngine::CreateSupremacySacred(s_nameBuffer);
        SacredSovereignty::SacredSovereigntyEngine::AssertDominance(supremacyId, s_dominanceInput);
        SacredSovereignty::SacredSovereigntyEngine::EstablishPreeminence(supremacyId, s_preeminenceInput);
        OnSupremacyAchieved(supremacyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Achieved Supremacies:");
    auto supremacies = SacredSovereignty::SacredSovereigntyEngine::GetAllSupremacySacreds();
    for (const auto& supremacy : supremacies) {
        ImGui::PushID(supremacy.supremacyId.c_str());
        if (ImGui::Selectable(supremacy.name.c_str(), s_selectedSupremacyId == supremacy.supremacyId)) {
            s_selectedSupremacyId = supremacy.supremacyId;
        }
        if (s_selectedSupremacyId == supremacy.supremacyId) {
            ImGui::Text("Supremacy: %.2f | Sacredness: %.2f | Dominance: %.2f | Preeminence: %.2f",
                supremacy.supremacy, supremacy.sacredness, supremacy.dominance, supremacy.preeminence);
        }
        ImGui::PopID();
    }
}

void SacredSovereigntyPanel::RenderSacredMetricsTab() {
    ImGui::Text("Sacred Sovereignty Metrics");
    ImGui::Separator();
    
    auto metrics = SacredSovereignty::SacredSovereigntyEngine::GetSacredSovereigntyMetrics();
    
    ImGui::Text("Sacred Count: %d", metrics["sacredCount"].get<int>());
    ImGui::Text("Sovereignty Count: %d", metrics["sovereigntyCount"].get<int>());
    ImGui::Text("Authority Count: %d", metrics["authorityCount"].get<int>());
    ImGui::Text("Dominion Count: %d", metrics["dominionCount"].get<int>());
    ImGui::Text("Supremacy Count: %d", metrics["supremacyCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Sacredness: %.4f", metrics["totalSacredness"].get<float>());
    ImGui::Text("Average Sacredness: %.4f", metrics["averageSacredness"].get<float>());
    ImGui::Text("Sacred Sacreds: %d", metrics["sacredSacreds"].get<int>());
    ImGui::Text("Total Sovereignty: %.4f", metrics["totalSovereignty"].get<float>());
    ImGui::Text("Absolute Sovereignties: %d", metrics["absoluteSovereignties"].get<int>());
    ImGui::Text("Vast Dominions: %d", metrics["vastDominions"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", SacredSovereignty::SacredSovereigntyLoop::GetTickCount());
    ImGui::Text("Loop FPS: %.1f", SacredSovereignty::SacredSovereigntyLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Sacred Report")) {
        auto report = SacredSovereignty::SacredSovereigntyEngine::GenerateSacredSovereigntyReport();
        // Export logic would go here
    }
}

void SacredSovereigntyPanel::RenderSacredVisualizationTab() {
    ImGui::Text("Sacred Sovereignty Visualization");
    ImGui::Separator();
    
    // Draw a representation of sacred sovereignty
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 25, 40, 255));
    
    // Draw sacred structures as violet orbs
    auto structures = SacredSovereignty::SacredSovereigntyEngine::GetAllSacredSovereigntyStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.sacredness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.authority * 10.0f;
        
        // Sacred glow effect (violet)
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 150, 255, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 180, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw sovereignty sacreds as absolute rays
    auto sovereignties = SacredSovereignty::SacredSovereigntyEngine::GetAllSovereigntySacreds();
    int sovereigntyIdx = 0;
    for (const auto& sovereignty : sovereignties) {
        float angle = (sovereigntyIdx * 2.0f * 3.14159f) / std::max(1, (int)sovereignties.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + sovereignty.rule * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = sovereignty.isAbsolute ? 
            IM_COL32(200, 150, 255, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + sovereignty.sovereignty * 3.0f);
        sovereigntyIdx++;
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
