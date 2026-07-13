#include "ide/BlessedEternityPanel.hpp"
#include "blessed/BlessedEternityEngine.hpp"
#include "blessed/BlessedEternityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool BlessedEternityPanel::s_visible = false;
bool BlessedEternityPanel::s_initialized = false;
int BlessedEternityPanel::s_selectedTab = 0;
char BlessedEternityPanel::s_nameBuffer[256] = {};
char BlessedEternityPanel::s_entityIdBuffer[256] = {};
char BlessedEternityPanel::s_attributeKeyBuffer[256] = {};
char BlessedEternityPanel::s_attributeValueBuffer[512] = {};
float BlessedEternityPanel::s_blessednessInput = 0.1f;
float BlessedEternityPanel::s_eternityInput = 0.1f;
float BlessedEternityPanel::s_graceInput = 0.1f;
float BlessedEternityPanel::s_favorInput = 0.1f;
float BlessedEternityPanel::s_abundanceInput = 0.1f;
float BlessedEternityPanel::s_eternalityInput = 0.1f;
float BlessedEternityPanel::s_blessednessEternalInput = 0.1f;
float BlessedEternityPanel::s_perpetuityInput = 0.1f;
float BlessedEternityPanel::s_divinityInput = 0.1f;
float BlessedEternityPanel::s_blessednessDivineInput = 0.1f;
float BlessedEternityPanel::s_sanctityInput = 0.1f;
float BlessedEternityPanel::s_gloryInput = 0.1f;
float BlessedEternityPanel::s_sacrednessInput = 0.1f;
float BlessedEternityPanel::s_blessednessSacredInput = 0.1f;
float BlessedEternityPanel::s_reverenceInput = 0.1f;
float BlessedEternityPanel::s_holinessInput = 0.1f;
float BlessedEternityPanel::s_blessednessHolyInput = 0.1f;
float BlessedEternityPanel::s_consecrationInput = 0.1f;
std::string BlessedEternityPanel::s_selectedStructureId;
std::string BlessedEternityPanel::s_selectedEternalId;
std::string BlessedEternityPanel::s_selectedDivineId;
std::string BlessedEternityPanel::s_selectedSacredId;
std::string BlessedEternityPanel::s_selectedHolyId;
std::vector<nlohmann::json> BlessedEternityPanel::s_blessedEvents;

void BlessedEternityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Blessed::BlessedEternityEngine::Init();
    Blessed::BlessedEternityLoop::Init();
    Blessed::BlessedEternityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void BlessedEternityPanel::Shutdown() {
    if (!s_initialized) return;
    Blessed::BlessedEternityLoop::Shutdown();
    Blessed::BlessedEternityEngine::Shutdown();
    s_initialized = false;
}

void BlessedEternityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Blessed Eternity Panel", &s_visible);
    
    const char* tabs[] = {
        "Blessed Structure", "Eternal Blessed", "Divine Blessed",
        "Sacred Blessed", "Holy Blessed", "Blessed Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("BlessedTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderBlessedStructureTab(); break;
                    case 1: RenderEternalBlessedTab(); break;
                    case 2: RenderDivineBlessedTab(); break;
                    case 3: RenderSacredBlessedTab(); break;
                    case 4: RenderHolyBlessedTab(); break;
                    case 5: RenderBlessedMetricsTab(); break;
                    case 6: RenderBlessedVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool BlessedEternityPanel::IsVisible() {
    return s_visible;
}

void BlessedEternityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Blessed::BlessedEternityLoop::IsRunning()) {
        Blessed::BlessedEternityLoop::Start();
    }
}

void BlessedEternityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* BlessedEternityPanel::GetPanelName() {
    return "Blessed Eternity";
}

void BlessedEternityPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedEternityPanel::OnEternalEstablished(const std::string& eternalId) {
    nlohmann::json event;
    event["type"] = "eternal_established";
    event["eternalId"] = eternalId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedEternityPanel::OnDivineManifested(const std::string& divineId) {
    nlohmann::json event;
    event["type"] = "divine_manifested";
    event["divineId"] = divineId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedEternityPanel::OnSacredRealized(const std::string& sacredId) {
    nlohmann::json event;
    event["type"] = "sacred_realized";
    event["sacredId"] = sacredId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedEternityPanel::OnHolyDiscovered(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_discovered";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedEternityPanel::RenderBlessedStructureTab() {
    ImGui::Text("Blessed Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternity", &s_eternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Abundance", &s_abundanceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Blessed::BlessedEternityEngine::CreateBlessedStructure(s_nameBuffer);
        Blessed::BlessedEternityEngine::ExpandBlessedness(structureId, s_blessednessInput);
        Blessed::BlessedEternityEngine::DeepenEternity(structureId, s_eternityInput);
        Blessed::BlessedEternityEngine::IncreaseGrace(structureId, s_graceInput);
        Blessed::BlessedEternityEngine::IncreaseFavor(structureId, s_favorInput);
        Blessed::BlessedEternityEngine::MultiplyAbundance(structureId, s_abundanceInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Blessed::BlessedEternityEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.blessedId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.blessedId)) {
            s_selectedStructureId = structure.blessedId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nBlessedness: %.2f\nEternity: %.2f\nGrace: %.2f\nFavor: %.2f\nAbundance: %.2f",
                structure.blessedId.c_str(), structure.blessedness, structure.eternity, 
                structure.grace, structure.favor, structure.abundance);
        }
        ImGui::PopID();
    }
}

void BlessedEternityPanel::RenderEternalBlessedTab() {
    ImGui::Text("Eternal Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternality", &s_eternalityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessEternalInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Eternal")) {
        std::string eternalId = Blessed::BlessedEternityEngine::EstablishEternalBlessed(s_nameBuffer);
        Blessed::BlessedEternityEngine::ExpandEternality(eternalId, s_eternalityInput);
        Blessed::BlessedEternityEngine::IncreaseBlessedness(eternalId, s_blessednessEternalInput);
        Blessed::BlessedEternityEngine::ExtendPerpetuity(eternalId, s_perpetuityInput);
        OnEternalEstablished(eternalId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Eternals:");
    auto eternals = Blessed::BlessedEternityEngine::GetAllEternalBlesseds();
    for (const auto& eternal : eternals) {
        ImGui::PushID(eternal.eternalId.c_str());
        bool isSelected = s_selectedEternalId == eternal.eternalId;
        if (ImGui::Selectable(eternal.name.c_str(), isSelected)) {
            s_selectedEternalId = eternal.eternalId;
        }
        ImGui::SameLine();
        if (eternal.isEternal) {
            ImGui::TextColored(ImVec4(1, 0.8, 0, 1), "[ETERNAL]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[TEMPORAL]");
        }
        if (s_selectedEternalId == eternal.eternalId) {
            if (!eternal.isEternal && ImGui::Button("Declare Eternal")) {
                Blessed::BlessedEternityEngine::DeclareEternal(eternal.eternalId);
            }
        }
        ImGui::PopID();
    }
}

void BlessedEternityPanel::RenderDivineBlessedTab() {
    ImGui::Text("Divine Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessDivineInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctity", &s_sanctityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Glory", &s_gloryInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Divine")) {
        std::string divineId = Blessed::BlessedEternityEngine::ManifestDivineBlessed(s_nameBuffer);
        Blessed::BlessedEternityEngine::ElevateDivinity(divineId, s_divinityInput);
        Blessed::BlessedEternityEngine::ExpandBlessednessDivine(divineId, s_blessednessDivineInput);
        Blessed::BlessedEternityEngine::IncreaseSanctity(divineId, s_sanctityInput);
        Blessed::BlessedEternityEngine::BestowGlory(divineId, s_gloryInput);
        OnDivineManifested(divineId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Divines:");
    auto divines = Blessed::BlessedEternityEngine::GetAllDivineBlesseds();
    for (const auto& divine : divines) {
        ImGui::PushID(divine.divineId.c_str());
        if (ImGui::Selectable(divine.name.c_str(), s_selectedDivineId == divine.divineId)) {
            s_selectedDivineId = divine.divineId;
        }
        if (s_selectedDivineId == divine.divineId) {
            ImGui::Text("Divinity: %.2f | Blessedness: %.2f | Sanctity: %.2f | Glory: %.2f",
                divine.divinity, divine.blessedness, divine.sanctity, divine.glory);
            ImGui::Text("Divine Manifestations: %zu", divine.divineManifestations.size());
        }
        ImGui::PopID();
    }
}

void BlessedEternityPanel::RenderSacredBlessedTab() {
    ImGui::Text("Sacred Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessSacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Reverence", &s_reverenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Sacred")) {
        std::string sacredId = Blessed::BlessedEternityEngine::RealizeSacredBlessed(s_nameBuffer);
        Blessed::BlessedEternityEngine::AmplifySacredness(sacredId, s_sacrednessInput);
        Blessed::BlessedEternityEngine::ExpandBlessednessSacred(sacredId, s_blessednessSacredInput);
        Blessed::BlessedEternityEngine::DeepenReverence(sacredId, s_reverenceInput);
        OnSacredRealized(sacredId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Sacred:");
    auto sacreds = Blessed::BlessedEternityEngine::GetAllSacredBlesseds();
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
            ImGui::Text("Sacredness: %.2f | Blessedness: %.2f | Reverence: %.2f",
                sacred.sacredness, sacred.blessedness, sacred.reverence);
            if (!sacred.isSacred && ImGui::Button("Declare Sacred")) {
                Blessed::BlessedEternityEngine::DeclareSacred(sacred.sacredId);
            }
        }
        ImGui::PopID();
    }
}

void BlessedEternityPanel::RenderHolyBlessedTab() {
    ImGui::Text("Holy Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Holy")) {
        std::string holyId = Blessed::BlessedEternityEngine::DiscoverHolyBlessed(s_nameBuffer);
        Blessed::BlessedEternityEngine::IncreaseHoliness(holyId, s_holinessInput);
        Blessed::BlessedEternityEngine::ExpandBlessednessHoly(holyId, s_blessednessHolyInput);
        Blessed::BlessedEternityEngine::Consecrate(holyId, s_consecrationInput);
        OnHolyDiscovered(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Holy:");
    auto holies = Blessed::BlessedEternityEngine::GetAllHolyBlesseds();
    for (const auto& holy : holies) {
        ImGui::PushID(holy.holyId.c_str());
        if (ImGui::Selectable(holy.name.c_str(), s_selectedHolyId == holy.holyId)) {
            s_selectedHolyId = holy.holyId;
        }
        if (s_selectedHolyId == holy.holyId) {
            ImGui::Text("Holiness: %.2f | Blessedness: %.2f | Consecration: %.2f",
                holy.holiness, holy.blessedness, holy.consecration);
            ImGui::Text("Holy Aspects: %zu", holy.holyAspects.size());
        }
        ImGui::PopID();
    }
}

void BlessedEternityPanel::RenderBlessedMetricsTab() {
    ImGui::Text("Blessed Metrics");
    ImGui::Separator();
    
    auto metrics = Blessed::BlessedEternityEngine::GetBlessedMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Eternal Count: %d", metrics["eternalCount"].get<int>());
    ImGui::Text("Divine Count: %d", metrics["divineCount"].get<int>());
    ImGui::Text("Sacred Count: %d", metrics["sacredCount"].get<int>());
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Blessedness: %.4f", metrics["totalBlessedness"].get<float>());
    ImGui::Text("Average Blessedness: %.4f", metrics["averageBlessedness"].get<float>());
    ImGui::Text("Eternal Blesseds: %d", metrics["eternalBlesseds"].get<int>());
    ImGui::Text("Average Divinity: %.4f", metrics["averageDivinity"].get<float>());
    ImGui::Text("Sacred Blesseds: %d", metrics["sacredBlesseds"].get<int>());
    ImGui::Text("Holy Blesseds: %d", metrics["holyBlesseds"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Blessed::BlessedEternityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Blessed Report")) {
        auto report = Blessed::BlessedEternityEngine::GenerateBlessedReport();
        // Export logic would go here
    }
}

void BlessedEternityPanel::RenderBlessedVisualizationTab() {
    ImGui::Text("Blessed Eternity Visualization");
    ImGui::Separator();
    
    // Draw a representation of blessed eternity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(10, 25, 10, 255));
    
    // Draw blessed structures as golden orbs
    auto structures = Blessed::BlessedEternityEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.blessedness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.grace * 10.0f;
        
        // Blessed glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(255, 215, 100, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 230, 150, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw eternal blesseds as expanding rings
    auto eternals = Blessed::BlessedEternityEngine::GetAllEternalBlesseds();
    int eternalIdx = 0;
    for (const auto& eternal : eternals) {
        float baseRadius = 30.0f + eternalIdx * 25.0f;
        float pulse = std::sin(ImGui::GetTime() * 2.0f + eternalIdx) * 5.0f;
        float radius = baseRadius + pulse;
        
        ImU32 color = eternal.isEternal ? 
            IM_COL32(255, 200, 100, 150) : IM_COL32(150, 150, 150, 100);
        draw_list->AddCircle(ImVec2(centerX, centerY), radius, color, 64, 2.0f);
        eternalIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Blessed Event Log:");
    ImGui::BeginChild("BlessedEvents", ImVec2(0, 150), true);
    for (auto it = s_blessedEvents.rbegin(); it != s_blessedEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
