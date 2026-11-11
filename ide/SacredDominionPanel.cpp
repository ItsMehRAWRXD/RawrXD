#include "ide/SacredDominionPanel.hpp"
#include "sacred/SacredDominionEngine.hpp"
#include "sacred/SacredDominionLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SacredDominionPanel::s_visible = false;
bool SacredDominionPanel::s_initialized = false;
int SacredDominionPanel::s_selectedTab = 0;
char SacredDominionPanel::s_nameBuffer[256] = {};
char SacredDominionPanel::s_entityIdBuffer[256] = {};
char SacredDominionPanel::s_attributeKeyBuffer[256] = {};
char SacredDominionPanel::s_attributeValueBuffer[512] = {};
float SacredDominionPanel::s_sacrednessInput = 0.1f;
float SacredDominionPanel::s_dominionInput = 0.1f;
float SacredDominionPanel::s_authorityInput = 0.1f;
float SacredDominionPanel::s_reverenceInput = 0.1f;
float SacredDominionPanel::s_sanctityInput = 0.1f;
float SacredDominionPanel::s_dominionSacredInput = 0.1f;
float SacredDominionPanel::s_sacrednessDominionInput = 0.1f;
float SacredDominionPanel::s_sovereigntyInput = 0.1f;
float SacredDominionPanel::s_holinessInput = 0.1f;
float SacredDominionPanel::s_sacrednessHolyInput = 0.1f;
float SacredDominionPanel::s_graceInput = 0.1f;
float SacredDominionPanel::s_blessingInput = 0.1f;
float SacredDominionPanel::s_blessednessInput = 0.1f;
float SacredDominionPanel::s_sacrednessBlessedInput = 0.1f;
float SacredDominionPanel::s_favorInput = 0.1f;
float SacredDominionPanel::s_sanctificationInput = 0.1f;
float SacredDominionPanel::s_sacrednessSanctifiedInput = 0.1f;
float SacredDominionPanel::s_consecrationInput = 0.1f;
std::string SacredDominionPanel::s_selectedStructureId;
std::string SacredDominionPanel::s_selectedDominionId;
std::string SacredDominionPanel::s_selectedHolyId;
std::string SacredDominionPanel::s_selectedBlessedId;
std::string SacredDominionPanel::s_selectedSanctifiedId;
std::vector<nlohmann::json> SacredDominionPanel::s_sacredEvents;

void SacredDominionPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    SacredDominion::SacredDominionEngine::Init();
    SacredDominion::SacredDominionLoop::Init();
    SacredDominion::SacredDominionLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SacredDominionPanel::Shutdown() {
    if (!s_initialized) return;
    SacredDominion::SacredDominionLoop::Shutdown();
    SacredDominion::SacredDominionEngine::Shutdown();
    s_initialized = false;
}

void SacredDominionPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sacred Dominion Panel", &s_visible);
    
    const char* tabs[] = {
        "Sacred Structure", "Dominion Sacred", "Holy Sacred",
        "Blessed Sacred", "Sanctified Sacred", "Sacred Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SacredTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSacredStructureTab(); break;
                    case 1: RenderDominionSacredTab(); break;
                    case 2: RenderHolySacredTab(); break;
                    case 3: RenderBlessedSacredTab(); break;
                    case 4: RenderSanctifiedSacredTab(); break;
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

bool SacredDominionPanel::IsVisible() {
    return s_visible;
}

void SacredDominionPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !SacredDominion::SacredDominionLoop::IsRunning()) {
        SacredDominion::SacredDominionLoop::Start();
    }
}

void SacredDominionPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SacredDominionPanel::GetPanelName() {
    return "Sacred Dominion";
}

void SacredDominionPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredDominionPanel::OnDominionEstablished(const std::string& dominionId) {
    nlohmann::json event;
    event["type"] = "dominion_established";
    event["dominionId"] = dominionId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredDominionPanel::OnHolyManifested(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_manifested";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredDominionPanel::OnBlessedRealized(const std::string& blessedId) {
    nlohmann::json event;
    event["type"] = "blessed_realized";
    event["blessedId"] = blessedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredDominionPanel::OnSanctifiedDiscovered(const std::string& sanctifiedId) {
    nlohmann::json event;
    event["type"] = "sanctified_discovered";
    event["sanctifiedId"] = sanctifiedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacredEvents.push_back(event);
}

void SacredDominionPanel::RenderSacredStructureTab() {
    ImGui::Text("Sacred Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Reverence", &s_reverenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctity", &s_sanctityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = SacredDominion::SacredDominionEngine::CreateSacredStructure(s_nameBuffer);
        SacredDominion::SacredDominionEngine::ExpandSacredness(structureId, s_sacrednessInput);
        SacredDominion::SacredDominionEngine::ExtendDominion(structureId, s_dominionInput);
        SacredDominion::SacredDominionEngine::IncreaseAuthority(structureId, s_authorityInput);
        SacredDominion::SacredDominionEngine::DeepenReverence(structureId, s_reverenceInput);
        SacredDominion::SacredDominionEngine::ElevateSanctity(structureId, s_sanctityInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = SacredDominion::SacredDominionEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.sacredId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.sacredId)) {
            s_selectedStructureId = structure.sacredId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSacredness: %.2f\nDominion: %.2f\nAuthority: %.2f\nReverence: %.2f\nSanctity: %.2f",
                structure.sacredId.c_str(), structure.sacredness, structure.dominion, 
                structure.authority, structure.reverence, structure.sanctity);
        }
        ImGui::PopID();
    }
}

void SacredDominionPanel::RenderDominionSacredTab() {
    ImGui::Text("Dominion Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Dominion", &s_dominionSacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessDominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sovereignty", &s_sovereigntyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Dominion")) {
        std::string dominionId = SacredDominion::SacredDominionEngine::EstablishDominionSacred(s_nameBuffer);
        SacredDominion::SacredDominionEngine::ExpandDominion(dominionId, s_dominionSacredInput);
        SacredDominion::SacredDominionEngine::IncreaseSacredness(dominionId, s_sacrednessDominionInput);
        SacredDominion::SacredDominionEngine::AssertSovereignty(dominionId, s_sovereigntyInput);
        OnDominionEstablished(dominionId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Dominions:");
    auto dominions = SacredDominion::SacredDominionEngine::GetAllDominionSacreds();
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
                SacredDominion::SacredDominionEngine::DeclareDominion(dominion.dominionId);
            }
        }
        ImGui::PopID();
    }
}

void SacredDominionPanel::RenderHolySacredTab() {
    ImGui::Text("Holy Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessing", &s_blessingInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Holy")) {
        std::string holyId = SacredDominion::SacredDominionEngine::ManifestHolySacred(s_nameBuffer);
        SacredDominion::SacredDominionEngine::ElevateHoliness(holyId, s_holinessInput);
        SacredDominion::SacredDominionEngine::ExpandSacrednessHoly(holyId, s_sacrednessHolyInput);
        SacredDominion::SacredDominionEngine::BestowGrace(holyId, s_graceInput);
        SacredDominion::SacredDominionEngine::GrantBlessing(holyId, s_blessingInput);
        OnHolyManifested(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Holies:");
    auto holies = SacredDominion::SacredDominionEngine::GetAllHolySacreds();
    for (const auto& holy : holies) {
        ImGui::PushID(holy.holyId.c_str());
        if (ImGui::Selectable(holy.name.c_str(), s_selectedHolyId == holy.holyId)) {
            s_selectedHolyId = holy.holyId;
        }
        if (s_selectedHolyId == holy.holyId) {
            ImGui::Text("Holiness: %.2f | Sacredness: %.2f | Grace: %.2f | Blessing: %.2f",
                holy.holiness, holy.sacredness, holy.grace, holy.blessing);
            ImGui::Text("Holy Manifestations: %zu", holy.holyManifestations.size());
        }
        ImGui::PopID();
    }
}

void SacredDominionPanel::RenderBlessedSacredTab() {
    ImGui::Text("Blessed Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Blessed")) {
        std::string blessedId = SacredDominion::SacredDominionEngine::RealizeBlessedSacred(s_nameBuffer);
        SacredDominion::SacredDominionEngine::AmplifyBlessedness(blessedId, s_blessednessInput);
        SacredDominion::SacredDominionEngine::ExpandSacrednessBlessed(blessedId, s_sacrednessBlessedInput);
        SacredDominion::SacredDominionEngine::IncreaseFavor(blessedId, s_favorInput);
        OnBlessedRealized(blessedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Blessed:");
    auto blessed = SacredDominion::SacredDominionEngine::GetAllBlessedSacreds();
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
            ImGui::Text("Blessedness: %.2f | Sacredness: %.2f | Favor: %.2f",
                b.blessedness, b.sacredness, b.favor);
            if (!b.isBlessed && ImGui::Button("Declare Blessed")) {
                SacredDominion::SacredDominionEngine::DeclareBlessed(b.blessedId);
            }
        }
        ImGui::PopID();
    }
}

void SacredDominionPanel::RenderSanctifiedSacredTab() {
    ImGui::Text("Sanctified Sacred Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctification", &s_sanctificationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Sanctified")) {
        std::string sanctifiedId = SacredDominion::SacredDominionEngine::DiscoverSanctifiedSacred(s_nameBuffer);
        SacredDominion::SacredDominionEngine::IncreaseSanctification(sanctifiedId, s_sanctificationInput);
        SacredDominion::SacredDominionEngine::ExpandSacrednessSanctified(sanctifiedId, s_sacrednessSanctifiedInput);
        SacredDominion::SacredDominionEngine::Consecrate(sanctifiedId, s_consecrationInput);
        OnSanctifiedDiscovered(sanctifiedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Sanctified:");
    auto sanctified = SacredDominion::SacredDominionEngine::GetAllSanctifiedSacreds();
    for (const auto& s : sanctified) {
        ImGui::PushID(s.sanctifiedId.c_str());
        if (ImGui::Selectable(s.name.c_str(), s_selectedSanctifiedId == s.sanctifiedId)) {
            s_selectedSanctifiedId = s.sanctifiedId;
        }
        if (s_selectedSanctifiedId == s.sanctifiedId) {
            ImGui::Text("Sanctification: %.2f | Sacredness: %.2f | Consecration: %.2f",
                s.sanctification, s.sacredness, s.consecration);
            ImGui::Text("Sanctified Aspects: %zu", s.sanctifiedAspects.size());
        }
        ImGui::PopID();
    }
}

void SacredDominionPanel::RenderSacredMetricsTab() {
    ImGui::Text("Sacred Metrics");
    ImGui::Separator();
    
    auto metrics = SacredDominion::SacredDominionEngine::GetSacredMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Dominion Count: %d", metrics["dominionCount"].get<int>());
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Text("Blessed Count: %d", metrics["blessedCount"].get<int>());
    ImGui::Text("Sanctified Count: %d", metrics["sanctifiedCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Sacredness: %.4f", metrics["totalSacredness"].get<float>());
    ImGui::Text("Average Sacredness: %.4f", metrics["averageSacredness"].get<float>());
    ImGui::Text("Dominion Sacreds: %d", metrics["dominionSacreds"].get<int>());
    ImGui::Text("Average Holiness: %.4f", metrics["averageHoliness"].get<float>());
    ImGui::Text("Blessed Sacreds: %d", metrics["blessedSacreds"].get<int>());
    ImGui::Text("Sanctified Sacreds: %d", metrics["sanctifiedSacreds"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", SacredDominion::SacredDominionLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Sacred Report")) {
        auto report = SacredDominion::SacredDominionEngine::GenerateSacredReport();
        // Export logic would go here
    }
}

void SacredDominionPanel::RenderSacredVisualizationTab() {
    ImGui::Text("Sacred Dominion Visualization");
    ImGui::Separator();
    
    // Draw a representation of sacred dominion
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(15, 10, 30, 255));
    
    // Draw sacred structures as radiant orbs
    auto structures = SacredDominion::SacredDominionEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.sacredness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.authority * 10.0f;
        
        // Sacred glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 150, 255, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 180, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw dominion sacreds as authority rays
    auto dominions = SacredDominion::SacredDominionEngine::GetAllDominionSacreds();
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
            IM_COL32(255, 200, 100, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + dominion.dominion * 3.0f);
        dominionIdx++;
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
