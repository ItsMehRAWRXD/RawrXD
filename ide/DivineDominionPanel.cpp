#include "ide/DivineDominionPanel.hpp"
#include "divine/DivineDominionEngine.hpp"
#include "divine/DivineDominionLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool DivineDominionPanel::s_visible = false;
bool DivineDominionPanel::s_initialized = false;
int DivineDominionPanel::s_selectedTab = 0;
char DivineDominionPanel::s_nameBuffer[256] = {};
char DivineDominionPanel::s_entityIdBuffer[256] = {};
char DivineDominionPanel::s_attributeKeyBuffer[256] = {};
char DivineDominionPanel::s_attributeValueBuffer[512] = {};
float DivineDominionPanel::s_divinityInput = 0.1f;
float DivineDominionPanel::s_dominionInput = 0.1f;
float DivineDominionPanel::s_sovereigntyInput = 0.1f;
float DivineDominionPanel::s_authorityInput = 0.1f;
float DivineDominionPanel::s_majestyInput = 0.1f;
float DivineDominionPanel::s_sovereigntySovereignInput = 0.1f;
float DivineDominionPanel::s_divinitySovereignInput = 0.1f;
float DivineDominionPanel::s_supremacyInput = 0.1f;
float DivineDominionPanel::s_eternalityInput = 0.1f;
float DivineDominionPanel::s_divinityEternalInput = 0.1f;
float DivineDominionPanel::s_perpetuityInput = 0.1f;
float DivineDominionPanel::s_gloryInput = 0.1f;
float DivineDominionPanel::s_sacrednessInput = 0.1f;
float DivineDominionPanel::s_divinitySacredInput = 0.1f;
float DivineDominionPanel::s_reverenceInput = 0.1f;
float DivineDominionPanel::s_holinessInput = 0.1f;
float DivineDominionPanel::s_divinityHolyInput = 0.1f;
float DivineDominionPanel::s_consecrationInput = 0.1f;
std::string DivineDominionPanel::s_selectedStructureId;
std::string DivineDominionPanel::s_selectedSovereignId;
std::string DivineDominionPanel::s_selectedEternalId;
std::string DivineDominionPanel::s_selectedSacredId;
std::string DivineDominionPanel::s_selectedHolyId;
std::vector<nlohmann::json> DivineDominionPanel::s_divineEvents;

void DivineDominionPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    DivineDominion::DivineDominionEngine::Init();
    DivineDominion::DivineDominionLoop::Init();
    DivineDominion::DivineDominionLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void DivineDominionPanel::Shutdown() {
    if (!s_initialized) return;
    DivineDominion::DivineDominionLoop::Shutdown();
    DivineDominion::DivineDominionEngine::Shutdown();
    s_initialized = false;
}

void DivineDominionPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Divine Dominion Panel", &s_visible);
    
    const char* tabs[] = {
        "Divine Structure", "Sovereign Divine", "Eternal Divine",
        "Sacred Divine", "Holy Divine", "Divine Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("DivineTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderDivineStructureTab(); break;
                    case 1: RenderSovereignDivineTab(); break;
                    case 2: RenderEternalDivineTab(); break;
                    case 3: RenderSacredDivineTab(); break;
                    case 4: RenderHolyDivineTab(); break;
                    case 5: RenderDivineMetricsTab(); break;
                    case 6: RenderDivineVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool DivineDominionPanel::IsVisible() {
    return s_visible;
}

void DivineDominionPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !DivineDominion::DivineDominionLoop::IsRunning()) {
        DivineDominion::DivineDominionLoop::Start();
    }
}

void DivineDominionPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* DivineDominionPanel::GetPanelName() {
    return "Divine Dominion";
}

void DivineDominionPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineDominionPanel::OnSovereignEstablished(const std::string& sovereignId) {
    nlohmann::json event;
    event["type"] = "sovereign_established";
    event["sovereignId"] = sovereignId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineDominionPanel::OnEternalManifested(const std::string& eternalId) {
    nlohmann::json event;
    event["type"] = "eternal_manifested";
    event["eternalId"] = eternalId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineDominionPanel::OnSacredRealized(const std::string& sacredId) {
    nlohmann::json event;
    event["type"] = "sacred_realized";
    event["sacredId"] = sacredId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineDominionPanel::OnHolyDiscovered(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_discovered";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineDominionPanel::RenderDivineStructureTab() {
    ImGui::Text("Divine Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sovereignty", &s_sovereigntyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Majesty", &s_majestyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = DivineDominion::DivineDominionEngine::CreateDivineStructure(s_nameBuffer);
        DivineDominion::DivineDominionEngine::ExpandDivinity(structureId, s_divinityInput);
        DivineDominion::DivineDominionEngine::ExtendDominion(structureId, s_dominionInput);
        DivineDominion::DivineDominionEngine::AssertSovereignty(structureId, s_sovereigntyInput);
        DivineDominion::DivineDominionEngine::IncreaseAuthority(structureId, s_authorityInput);
        DivineDominion::DivineDominionEngine::BestowMajesty(structureId, s_majestyInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = DivineDominion::DivineDominionEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.divineId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.divineId)) {
            s_selectedStructureId = structure.divineId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nDivinity: %.2f\nDominion: %.2f\nSovereignty: %.2f\nAuthority: %.2f\nMajesty: %.2f",
                structure.divineId.c_str(), structure.divinity, structure.dominion, 
                structure.sovereignty, structure.authority, structure.majesty);
        }
        ImGui::PopID();
    }
}

void DivineDominionPanel::RenderSovereignDivineTab() {
    ImGui::Text("Sovereign Divine Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sovereignty", &s_sovereigntySovereignInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinitySovereignInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Supremacy", &s_supremacyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Sovereign")) {
        std::string sovereignId = DivineDominion::DivineDominionEngine::EstablishSovereignDivine(s_nameBuffer);
        DivineDominion::DivineDominionEngine::ExpandSovereignty(sovereignId, s_sovereigntySovereignInput);
        DivineDominion::DivineDominionEngine::IncreaseDivinity(sovereignId, s_divinitySovereignInput);
        DivineDominion::DivineDominionEngine::AssertSupremacy(sovereignId, s_supremacyInput);
        OnSovereignEstablished(sovereignId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Sovereigns:");
    auto sovereigns = DivineDominion::DivineDominionEngine::GetAllSovereignDivines();
    for (const auto& sovereign : sovereigns) {
        ImGui::PushID(sovereign.sovereignId.c_str());
        bool isSelected = s_selectedSovereignId == sovereign.sovereignId;
        if (ImGui::Selectable(sovereign.name.c_str(), isSelected)) {
            s_selectedSovereignId = sovereign.sovereignId;
        }
        ImGui::SameLine();
        if (sovereign.isSovereign) {
            ImGui::TextColored(ImVec4(1, 0.8, 0, 1), "[SOVEREIGN]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[STANDARD]");
        }
        if (s_selectedSovereignId == sovereign.sovereignId) {
            if (!sovereign.isSovereign && ImGui::Button("Declare Sovereign")) {
                DivineDominion::DivineDominionEngine::DeclareSovereign(sovereign.sovereignId);
            }
        }
        ImGui::PopID();
    }
}

void DivineDominionPanel::RenderEternalDivineTab() {
    ImGui::Text("Eternal Divine Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternality", &s_eternalityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinityEternalInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Glory", &s_gloryInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Eternal")) {
        std::string eternalId = DivineDominion::DivineDominionEngine::ManifestEternalDivine(s_nameBuffer);
        DivineDominion::DivineDominionEngine::ElevateEternality(eternalId, s_eternalityInput);
        DivineDominion::DivineDominionEngine::ExpandDivinityEternal(eternalId, s_divinityEternalInput);
        DivineDominion::DivineDominionEngine::ExtendPerpetuity(eternalId, s_perpetuityInput);
        DivineDominion::DivineDominionEngine::BestowGlory(eternalId, s_gloryInput);
        OnEternalManifested(eternalId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Eternals:");
    auto eternals = DivineDominion::DivineDominionEngine::GetAllEternalDivines();
    for (const auto& eternal : eternals) {
        ImGui::PushID(eternal.eternalId.c_str());
        if (ImGui::Selectable(eternal.name.c_str(), s_selectedEternalId == eternal.eternalId)) {
            s_selectedEternalId = eternal.eternalId;
        }
        if (s_selectedEternalId == eternal.eternalId) {
            ImGui::Text("Eternality: %.2f | Divinity: %.2f | Perpetuity: %.2f | Glory: %.2f",
                eternal.eternality, eternal.divinity, eternal.perpetuity, eternal.glory);
            ImGui::Text("Eternal Manifestations: %zu", eternal.eternalManifestations.size());
        }
        ImGui::PopID();
    }
}

void DivineDominionPanel::RenderSacredDivineTab() {
    ImGui::Text("Sacred Divine Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinitySacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Reverence", &s_reverenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Sacred")) {
        std::string sacredId = DivineDominion::DivineDominionEngine::RealizeSacredDivine(s_nameBuffer);
        DivineDominion::DivineDominionEngine::AmplifySacredness(sacredId, s_sacrednessInput);
        DivineDominion::DivineDominionEngine::ExpandDivinitySacred(sacredId, s_divinitySacredInput);
        DivineDominion::DivineDominionEngine::DeepenReverence(sacredId, s_reverenceInput);
        OnSacredRealized(sacredId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Sacred:");
    auto sacreds = DivineDominion::DivineDominionEngine::GetAllSacredDivines();
    for (const auto& sacred : sacreds) {
        ImGui::PushID(sacred.sacredId.c_str());
        if (ImGui::Selectable(sacred.name.c_str(), s_selectedSacredId == sacred.sacredId)) {
            s_selectedSacredId = sacred.sacredId;
        }
        ImGui::SameLine();
        if (sacred.isSacred) {
            ImGui::TextColored(ImVec4(0, 1, 0.5f, 1), "[SACRED]");
        }
        if (s_selectedSacredId == sacred.sacredId) {
            ImGui::Text("Sacredness: %.2f | Divinity: %.2f | Reverence: %.2f",
                sacred.sacredness, sacred.divinity, sacred.reverence);
            if (!sacred.isSacred && ImGui::Button("Declare Sacred")) {
                DivineDominion::DivineDominionEngine::DeclareSacred(sacred.sacredId);
            }
        }
        ImGui::PopID();
    }
}

void DivineDominionPanel::RenderHolyDivineTab() {
    ImGui::Text("Holy Divine Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinityHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Holy")) {
        std::string holyId = DivineDominion::DivineDominionEngine::DiscoverHolyDivine(s_nameBuffer);
        DivineDominion::DivineDominionEngine::IncreaseHoliness(holyId, s_holinessInput);
        DivineDominion::DivineDominionEngine::ExpandDivinityHoly(holyId, s_divinityHolyInput);
        DivineDominion::DivineDominionEngine::Consecrate(holyId, s_consecrationInput);
        OnHolyDiscovered(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Holy:");
    auto holies = DivineDominion::DivineDominionEngine::GetAllHolyDivines();
    for (const auto& holy : holies) {
        ImGui::PushID(holy.holyId.c_str());
        if (ImGui::Selectable(holy.name.c_str(), s_selectedHolyId == holy.holyId)) {
            s_selectedHolyId = holy.holyId;
        }
        if (s_selectedHolyId == holy.holyId) {
            ImGui::Text("Holiness: %.2f | Divinity: %.2f | Consecration: %.2f",
                holy.holiness, holy.divinity, holy.consecration);
            ImGui::Text("Holy Aspects: %zu", holy.holyAspects.size());
        }
        ImGui::PopID();
    }
}

void DivineDominionPanel::RenderDivineMetricsTab() {
    ImGui::Text("Divine Metrics");
    ImGui::Separator();
    
    auto metrics = DivineDominion::DivineDominionEngine::GetDivineMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Sovereign Count: %d", metrics["sovereignCount"].get<int>());
    ImGui::Text("Eternal Count: %d", metrics["eternalCount"].get<int>());
    ImGui::Text("Sacred Count: %d", metrics["sacredCount"].get<int>());
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Divinity: %.4f", metrics["totalDivinity"].get<float>());
    ImGui::Text("Average Divinity: %.4f", metrics["averageDivinity"].get<float>());
    ImGui::Text("Sovereign Divines: %d", metrics["sovereignDivines"].get<int>());
    ImGui::Text("Average Eternality: %.4f", metrics["averageEternality"].get<float>());
    ImGui::Text("Sacred Divines: %d", metrics["sacredDivines"].get<int>());
    ImGui::Text("Holy Divines: %d", metrics["holyDivines"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", DivineDominion::DivineDominionLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Divine Report")) {
        auto report = DivineDominion::DivineDominionEngine::GenerateDivineReport();
        // Export logic would go here
    }
}

void DivineDominionPanel::RenderDivineVisualizationTab() {
    ImGui::Text("Divine Dominion Visualization");
    ImGui::Separator();
    
    // Draw a representation of divine dominion
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(25, 15, 35, 255));
    
    // Draw divine structures as golden orbs
    auto structures = DivineDominion::DivineDominionEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.divinity * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.authority * 10.0f;
        
        // Divine glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(255, 215, 100, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 230, 150, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw sovereign divines as authority rays
    auto sovereigns = DivineDominion::DivineDominionEngine::GetAllSovereignDivines();
    int sovereignIdx = 0;
    for (const auto& sovereign : sovereigns) {
        float angle = (sovereignIdx * 2.0f * 3.14159f) / std::max(1, (int)sovereigns.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + sovereign.supremacy * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = sovereign.isSovereign ? 
            IM_COL32(255, 200, 100, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + sovereign.sovereignty * 3.0f);
        sovereignIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Divine Event Log:");
    ImGui::BeginChild("DivineEvents", ImVec2(0, 150), true);
    for (auto it = s_divineEvents.rbegin(); it != s_divineEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
