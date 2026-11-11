#include "ide/SanctifiedInfinityPanel.hpp"
#include "sanctified/SanctifiedInfinityEngine.hpp"
#include "sanctified/SanctifiedInfinityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SanctifiedInfinityPanel::s_visible = false;
bool SanctifiedInfinityPanel::s_initialized = false;
int SanctifiedInfinityPanel::s_selectedTab = 0;
char SanctifiedInfinityPanel::s_nameBuffer[256] = {};
char SanctifiedInfinityPanel::s_entityIdBuffer[256] = {};
char SanctifiedInfinityPanel::s_attributeKeyBuffer[256] = {};
char SanctifiedInfinityPanel::s_attributeValueBuffer[512] = {};
float SanctifiedInfinityPanel::s_sanctificationInput = 0.1f;
float SanctifiedInfinityPanel::s_infinityInput = 0.1f;
float SanctifiedInfinityPanel::s_purityInput = 0.1f;
float SanctifiedInfinityPanel::s_consecrationInput = 0.1f;
float SanctifiedInfinityPanel::s_devotionInput = 0.1f;
float SanctifiedInfinityPanel::s_infinitudeInput = 0.1f;
float SanctifiedInfinityPanel::s_sanctificationInfiniteInput = 0.1f;
float SanctifiedInfinityPanel::s_perpetuityInput = 0.1f;
float SanctifiedInfinityPanel::s_divinityInput = 0.1f;
float SanctifiedInfinityPanel::s_sanctificationDivineInput = 0.1f;
float SanctifiedInfinityPanel::s_graceInput = 0.1f;
float SanctifiedInfinityPanel::s_gloryInput = 0.1f;
float SanctifiedInfinityPanel::s_sacrednessInput = 0.1f;
float SanctifiedInfinityPanel::s_sanctificationSacredInput = 0.1f;
float SanctifiedInfinityPanel::s_reverenceInput = 0.1f;
float SanctifiedInfinityPanel::s_holinessInput = 0.1f;
float SanctifiedInfinityPanel::s_sanctificationHolyInput = 0.1f;
float SanctifiedInfinityPanel::s_consecrationHolyInput = 0.1f;
std::string SanctifiedInfinityPanel::s_selectedStructureId;
std::string SanctifiedInfinityPanel::s_selectedInfiniteId;
std::string SanctifiedInfinityPanel::s_selectedDivineId;
std::string SanctifiedInfinityPanel::s_selectedSacredId;
std::string SanctifiedInfinityPanel::s_selectedHolyId;
std::vector<nlohmann::json> SanctifiedInfinityPanel::s_sanctifiedEvents;

void SanctifiedInfinityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Sanctified::SanctifiedInfinityEngine::Init();
    Sanctified::SanctifiedInfinityLoop::Init();
    Sanctified::SanctifiedInfinityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SanctifiedInfinityPanel::Shutdown() {
    if (!s_initialized) return;
    Sanctified::SanctifiedInfinityLoop::Shutdown();
    Sanctified::SanctifiedInfinityEngine::Shutdown();
    s_initialized = false;
}

void SanctifiedInfinityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sanctified Infinity Panel", &s_visible);
    
    const char* tabs[] = {
        "Sanctified Structure", "Infinite Sanctified", "Divine Sanctified",
        "Sacred Sanctified", "Holy Sanctified", "Sanctified Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SanctifiedTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSanctifiedStructureTab(); break;
                    case 1: RenderInfiniteSanctifiedTab(); break;
                    case 2: RenderDivineSanctifiedTab(); break;
                    case 3: RenderSacredSanctifiedTab(); break;
                    case 4: RenderHolySanctifiedTab(); break;
                    case 5: RenderSanctifiedMetricsTab(); break;
                    case 6: RenderSanctifiedVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool SanctifiedInfinityPanel::IsVisible() {
    return s_visible;
}

void SanctifiedInfinityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Sanctified::SanctifiedInfinityLoop::IsRunning()) {
        Sanctified::SanctifiedInfinityLoop::Start();
    }
}

void SanctifiedInfinityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SanctifiedInfinityPanel::GetPanelName() {
    return "Sanctified Infinity";
}

void SanctifiedInfinityPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedInfinityPanel::OnInfiniteEstablished(const std::string& infiniteId) {
    nlohmann::json event;
    event["type"] = "infinite_established";
    event["infiniteId"] = infiniteId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedInfinityPanel::OnDivineManifested(const std::string& divineId) {
    nlohmann::json event;
    event["type"] = "divine_manifested";
    event["divineId"] = divineId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedInfinityPanel::OnSacredRealized(const std::string& sacredId) {
    nlohmann::json event;
    event["type"] = "sacred_realized";
    event["sacredId"] = sacredId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedInfinityPanel::OnHolyDiscovered(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_discovered";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedInfinityPanel::RenderSanctifiedStructureTab() {
    ImGui::Text("Sanctified Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctification", &s_sanctificationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Purity", &s_purityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Devotion", &s_devotionInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Sanctified::SanctifiedInfinityEngine::CreateSanctifiedStructure(s_nameBuffer);
        Sanctified::SanctifiedInfinityEngine::ExpandSanctification(structureId, s_sanctificationInput);
        Sanctified::SanctifiedInfinityEngine::DeepenInfinity(structureId, s_infinityInput);
        Sanctified::SanctifiedInfinityEngine::Purify(structureId, s_purityInput);
        Sanctified::SanctifiedInfinityEngine::Consecrate(structureId, s_consecrationInput);
        Sanctified::SanctifiedInfinityEngine::IncreaseDevotion(structureId, s_devotionInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Sanctified::SanctifiedInfinityEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.sanctifiedId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.sanctifiedId)) {
            s_selectedStructureId = structure.sanctifiedId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSanctification: %.2f\nInfinity: %.2f\nPurity: %.2f\nConsecration: %.2f\nDevotion: %.2f",
                structure.sanctifiedId.c_str(), structure.sanctification, structure.infinity, 
                structure.purity, structure.consecration, structure.devotion);
        }
        ImGui::PopID();
    }
}

void SanctifiedInfinityPanel::RenderInfiniteSanctifiedTab() {
    ImGui::Text("Infinite Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Infinitude", &s_infinitudeInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationInfiniteInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Infinite")) {
        std::string infiniteId = Sanctified::SanctifiedInfinityEngine::EstablishInfiniteSanctified(s_nameBuffer);
        Sanctified::SanctifiedInfinityEngine::ExpandInfinitude(infiniteId, s_infinitudeInput);
        Sanctified::SanctifiedInfinityEngine::IncreaseSanctification(infiniteId, s_sanctificationInfiniteInput);
        Sanctified::SanctifiedInfinityEngine::ExtendPerpetuity(infiniteId, s_perpetuityInput);
        OnInfiniteEstablished(infiniteId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Infinites:");
    auto infinites = Sanctified::SanctifiedInfinityEngine::GetAllInfiniteSanctifieds();
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
                Sanctified::SanctifiedInfinityEngine::DeclareInfinite(infinite.infiniteId);
            }
        }
        ImGui::PopID();
    }
}

void SanctifiedInfinityPanel::RenderDivineSanctifiedTab() {
    ImGui::Text("Divine Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationDivineInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Glory", &s_gloryInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Divine")) {
        std::string divineId = Sanctified::SanctifiedInfinityEngine::ManifestDivineSanctified(s_nameBuffer);
        Sanctified::SanctifiedInfinityEngine::ElevateDivinity(divineId, s_divinityInput);
        Sanctified::SanctifiedInfinityEngine::ExpandSanctificationDivine(divineId, s_sanctificationDivineInput);
        Sanctified::SanctifiedInfinityEngine::BestowGrace(divineId, s_graceInput);
        Sanctified::SanctifiedInfinityEngine::BestowGlory(divineId, s_gloryInput);
        OnDivineManifested(divineId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Divines:");
    auto divines = Sanctified::SanctifiedInfinityEngine::GetAllDivineSanctifieds();
    for (const auto& divine : divines) {
        ImGui::PushID(divine.divineId.c_str());
        if (ImGui::Selectable(divine.name.c_str(), s_selectedDivineId == divine.divineId)) {
            s_selectedDivineId = divine.divineId;
        }
        if (s_selectedDivineId == divine.divineId) {
            ImGui::Text("Divinity: %.2f | Sanctification: %.2f | Grace: %.2f | Glory: %.2f",
                divine.divinity, divine.sanctification, divine.grace, divine.glory);
            ImGui::Text("Divine Manifestations: %zu", divine.divineManifestations.size());
        }
        ImGui::PopID();
    }
}

void SanctifiedInfinityPanel::RenderSacredSanctifiedTab() {
    ImGui::Text("Sacred Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationSacredInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Reverence", &s_reverenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Sacred")) {
        std::string sacredId = Sanctified::SanctifiedInfinityEngine::RealizeSacredSanctified(s_nameBuffer);
        Sanctified::SanctifiedInfinityEngine::AmplifySacredness(sacredId, s_sacrednessInput);
        Sanctified::SanctifiedInfinityEngine::ExpandSanctificationSacred(sacredId, s_sanctificationSacredInput);
        Sanctified::SanctifiedInfinityEngine::DeepenReverence(sacredId, s_reverenceInput);
        OnSacredRealized(sacredId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Sacred:");
    auto sacreds = Sanctified::SanctifiedInfinityEngine::GetAllSacredSanctifieds();
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
            ImGui::Text("Sacredness: %.2f | Sanctification: %.2f | Reverence: %.2f",
                sacred.sacredness, sacred.sanctification, sacred.reverence);
            if (!sacred.isSacred && ImGui::Button("Declare Sacred")) {
                Sanctified::SanctifiedInfinityEngine::DeclareSacred(sacred.sacredId);
            }
        }
        ImGui::PopID();
    }
}

void SanctifiedInfinityPanel::RenderHolySanctifiedTab() {
    ImGui::Text("Holy Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationHolyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Holy")) {
        std::string holyId = Sanctified::SanctifiedInfinityEngine::DiscoverHolySanctified(s_nameBuffer);
        Sanctified::SanctifiedInfinityEngine::IncreaseHoliness(holyId, s_holinessInput);
        Sanctified::SanctifiedInfinityEngine::ExpandSanctificationHoly(holyId, s_sanctificationHolyInput);
        Sanctified::SanctifiedInfinityEngine::ConsecrateHoly(holyId, s_consecrationHolyInput);
        OnHolyDiscovered(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Holy:");
    auto holies = Sanctified::SanctifiedInfinityEngine::GetAllHolySanctifieds();
    for (const auto& holy : holies) {
        ImGui::PushID(holy.holyId.c_str());
        if (ImGui::Selectable(holy.name.c_str(), s_selectedHolyId == holy.holyId)) {
            s_selectedHolyId = holy.holyId;
        }
        if (s_selectedHolyId == holy.holyId) {
            ImGui::Text("Holiness: %.2f | Sanctification: %.2f | Consecration: %.2f",
                holy.holiness, holy.sanctification, holy.consecration);
            ImGui::Text("Holy Aspects: %zu", holy.holyAspects.size());
        }
        ImGui::PopID();
    }
}

void SanctifiedInfinityPanel::RenderSanctifiedMetricsTab() {
    ImGui::Text("Sanctified Metrics");
    ImGui::Separator();
    
    auto metrics = Sanctified::SanctifiedInfinityEngine::GetSanctifiedMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Infinite Count: %d", metrics["infiniteCount"].get<int>());
    ImGui::Text("Divine Count: %d", metrics["divineCount"].get<int>());
    ImGui::Text("Sacred Count: %d", metrics["sacredCount"].get<int>());
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Sanctification: %.4f", metrics["totalSanctification"].get<float>());
    ImGui::Text("Average Sanctification: %.4f", metrics["averageSanctification"].get<float>());
    ImGui::Text("Infinite Sanctifieds: %d", metrics["infiniteSanctifieds"].get<int>());
    ImGui::Text("Average Divinity: %.4f", metrics["averageDivinity"].get<float>());
    ImGui::Text("Sacred Sanctifieds: %d", metrics["sacredSanctifieds"].get<int>());
    ImGui::Text("Holy Sanctifieds: %d", metrics["holySanctifieds"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Sanctified::SanctifiedInfinityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Sanctified Report")) {
        auto report = Sanctified::SanctifiedInfinityEngine::GenerateSanctifiedReport();
        // Export logic would go here
    }
}

void SanctifiedInfinityPanel::RenderSanctifiedVisualizationTab() {
    ImGui::Text("Sanctified Infinity Visualization");
    ImGui::Separator();
    
    // Draw a representation of sanctified infinity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 10, 30, 255));
    
    // Draw sanctified structures as radiant orbs
    auto structures = Sanctified::SanctifiedInfinityEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.sanctification * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.purity * 10.0f;
        
        // Sanctified glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 150, 255, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 180, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw infinite sanctifieds as expanding rings
    auto infinites = Sanctified::SanctifiedInfinityEngine::GetAllInfiniteSanctifieds();
    int infiniteIdx = 0;
    for (const auto& infinite : infinites) {
        float baseRadius = 30.0f + infiniteIdx * 25.0f;
        float pulse = std::sin(ImGui::GetTime() * 2.0f + infiniteIdx) * 5.0f;
        float radius = baseRadius + pulse;
        
        ImU32 color = infinite.isInfinite ? 
            IM_COL32(200, 150, 255, 150) : IM_COL32(150, 150, 150, 100);
        draw_list->AddCircle(ImVec2(centerX, centerY), radius, color, 64, 2.0f);
        infiniteIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Sanctified Event Log:");
    ImGui::BeginChild("SanctifiedEvents", ImVec2(0, 150), true);
    for (auto it = s_sanctifiedEvents.rbegin(); it != s_sanctifiedEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
