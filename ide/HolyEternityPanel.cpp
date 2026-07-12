#include "ide/HolyEternityPanel.hpp"
#include "holy/HolyEternityEngine.hpp"
#include "holy/HolyEternityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool HolyEternityPanel::s_visible = false;
bool HolyEternityPanel::s_initialized = false;
int HolyEternityPanel::s_selectedTab = 0;
char HolyEternityPanel::s_nameBuffer[256] = {};
char HolyEternityPanel::s_entityIdBuffer[256] = {};
char HolyEternityPanel::s_attributeKeyBuffer[256] = {};
char HolyEternityPanel::s_attributeValueBuffer[512] = {};
float HolyEternityPanel::s_holinessInput = 0.1f;
float HolyEternityPanel::s_eternityInput = 0.1f;
float HolyEternityPanel::s_divinityInput = 0.1f;
float HolyEternityPanel::s_transcendenceInput = 0.1f;
float HolyEternityPanel::s_graceInput = 0.1f;
float HolyEternityPanel::s_eternityHolyInput = 0.1f;
float HolyEternityPanel::s_holinessEternityInput = 0.1f;
float HolyEternityPanel::s_infinityInput = 0.1f;
float HolyEternityPanel::s_perpetuityInput = 0.1f;
float HolyEternityPanel::s_divineHolyInput = 0.1f;
float HolyEternityPanel::s_holinessDivineInput = 0.1f;
float HolyEternityPanel::s_sacrednessInput = 0.1f;
float HolyEternityPanel::s_blessingInput = 0.1f;
float HolyEternityPanel::s_transcendentHolyInput = 0.1f;
float HolyEternityPanel::s_holinessTranscendentInput = 0.1f;
float HolyEternityPanel::s_elevationInput = 0.1f;
float HolyEternityPanel::s_ascensionInput = 0.1f;
float HolyEternityPanel::s_graceHolyInput = 0.1f;
float HolyEternityPanel::s_holinessGraceInput = 0.1f;
float HolyEternityPanel::s_mercyInput = 0.1f;
float HolyEternityPanel::s_favorInput = 0.1f;
std::string HolyEternityPanel::s_selectedHolyId;
std::string HolyEternityPanel::s_selectedEternityId;
std::string HolyEternityPanel::s_selectedDivineId;
std::string HolyEternityPanel::s_selectedTranscendentId;
std::string HolyEternityPanel::s_selectedGraceId;
std::vector<nlohmann::json> HolyEternityPanel::s_holyEvents;

void HolyEternityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    HolyEternity::HolyEternityEngine::Init();
    HolyEternity::HolyEternityLoop::Init();
    HolyEternity::HolyEternityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void HolyEternityPanel::Shutdown() {
    if (!s_initialized) return;
    HolyEternity::HolyEternityLoop::Shutdown();
    HolyEternity::HolyEternityEngine::Shutdown();
    s_initialized = false;
}

void HolyEternityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Holy Eternity Panel", &s_visible);
    
    const char* tabs[] = {
        "Holy Structure", "Eternity Holy", "Divine Holy",
        "Transcendent Holy", "Grace Holy", "Holy Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("HolyTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderHolyStructureTab(); break;
                    case 1: RenderEternityHolyTab(); break;
                    case 2: RenderDivineHolyTab(); break;
                    case 3: RenderTranscendentHolyTab(); break;
                    case 4: RenderGraceHolyTab(); break;
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

bool HolyEternityPanel::IsVisible() {
    return s_visible;
}

void HolyEternityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !HolyEternity::HolyEternityLoop::IsRunning()) {
        HolyEternity::HolyEternityLoop::Start();
    }
}

void HolyEternityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* HolyEternityPanel::GetPanelName() {
    return "Holy Eternity";
}

void HolyEternityPanel::OnHolyStructureCreated(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_structure_created";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyEternityPanel::OnEternityEstablished(const std::string& eternityId) {
    nlohmann::json event;
    event["type"] = "eternity_established";
    event["eternityId"] = eternityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyEternityPanel::OnDivineManifested(const std::string& divineId) {
    nlohmann::json event;
    event["type"] = "divine_manifested";
    event["divineId"] = divineId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyEternityPanel::OnTranscendentRealized(const std::string& transcendentId) {
    nlohmann::json event;
    event["type"] = "transcendent_realized";
    event["transcendentId"] = transcendentId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyEternityPanel::OnGraceBestowed(const std::string& graceId) {
    nlohmann::json event;
    event["type"] = "grace_bestowed";
    event["graceId"] = graceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyEternityPanel::RenderHolyStructureTab() {
    ImGui::Text("Holy Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternity", &s_eternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string holyId = HolyEternity::HolyEternityEngine::CreateHolyEternityStructure(s_nameBuffer);
        HolyEternity::HolyEternityEngine::ElevateHoliness(holyId, s_holinessInput);
        HolyEternity::HolyEternityEngine::ExpandEternity(holyId, s_eternityInput);
        HolyEternity::HolyEternityEngine::IncreaseDivinity(holyId, s_divinityInput);
        HolyEternity::HolyEternityEngine::DeepenTranscendence(holyId, s_transcendenceInput);
        HolyEternity::HolyEternityEngine::BestowGrace(holyId, s_graceInput);
        OnHolyStructureCreated(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = HolyEternity::HolyEternityEngine::GetAllHolyEternityStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.holyId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedHolyId == structure.holyId)) {
            s_selectedHolyId = structure.holyId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nHoliness: %.2f\nEternity: %.2f\nDivinity: %.2f\nTranscendence: %.2f\nGrace: %.2f",
                structure.holyId.c_str(), structure.holiness, structure.eternity, 
                structure.divinity, structure.transcendence, structure.grace);
        }
        ImGui::PopID();
    }
}

void HolyEternityPanel::RenderEternityHolyTab() {
    ImGui::Text("Eternity Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternity", &s_eternityHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessEternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Eternity")) {
        std::string eternityId = HolyEternity::HolyEternityEngine::CreateEternityHoly(s_nameBuffer);
        HolyEternity::HolyEternityEngine::PerpetuateEternity(eternityId, s_eternityHolyInput);
        HolyEternity::HolyEternityEngine::ExpandInfinity(eternityId, s_infinityInput);
        OnEternityEstablished(eternityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Eternities:");
    auto eternities = HolyEternity::HolyEternityEngine::GetAllEternityHolies();
    for (const auto& eternity : eternities) {
        ImGui::PushID(eternity.eternityId.c_str());
        bool isSelected = s_selectedEternityId == eternity.eternityId;
        if (ImGui::Selectable(eternity.name.c_str(), isSelected)) {
            s_selectedEternityId = eternity.eternityId;
        }
        ImGui::SameLine();
        if (eternity.isEternal) {
            ImGui::TextColored(ImVec4(0, 1, 0.8f, 1), "[ETERNAL]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[TEMPORAL]");
        }
        if (s_selectedEternityId == eternity.eternityId) {
            if (!eternity.isEternal && ImGui::Button("Declare Eternal")) {
                HolyEternity::HolyEternityEngine::DeclareEternal(eternity.eternityId);
            }
        }
        ImGui::PopID();
    }
}

void HolyEternityPanel::RenderDivineHolyTab() {
    ImGui::Text("Divine Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Divinity", &s_divineHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessDivineInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessing", &s_blessingInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Divine")) {
        std::string divineId = HolyEternity::HolyEternityEngine::CreateDivineHoly(s_nameBuffer);
        HolyEternity::HolyEternityEngine::BlessDivine(divineId, s_blessingInput);
        HolyEternity::HolyEternityEngine::SanctifyDivine(divineId, s_sacrednessInput);
        OnDivineManifested(divineId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Divines:");
    auto divines = HolyEternity::HolyEternityEngine::GetAllDivineHolies();
    for (const auto& divine : divines) {
        ImGui::PushID(divine.divineId.c_str());
        if (ImGui::Selectable(divine.name.c_str(), s_selectedDivineId == divine.divineId)) {
            s_selectedDivineId = divine.divineId;
        }
        if (s_selectedDivineId == divine.divineId) {
            ImGui::Text("Divinity: %.2f | Holiness: %.2f | Sacredness: %.2f | Blessing: %.2f",
                divine.divinity, divine.holiness, divine.sacredness, divine.blessing);
        }
        ImGui::PopID();
    }
}

void HolyEternityPanel::RenderTranscendentHolyTab() {
    ImGui::Text("Transcendent Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Transcendence", &s_transcendentHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessTranscendentInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Elevation", &s_elevationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Ascension", &s_ascensionInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Transcendent")) {
        std::string transcendentId = HolyEternity::HolyEternityEngine::CreateTranscendentHoly(s_nameBuffer);
        HolyEternity::HolyEternityEngine::ElevateTranscendence(transcendentId, s_elevationInput);
        HolyEternity::HolyEternityEngine::AscendTranscendent(transcendentId, s_ascensionInput);
        OnTranscendentRealized(transcendentId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Transcendents:");
    auto transcendents = HolyEternity::HolyEternityEngine::GetAllTranscendentHolies();
    for (const auto& transcendent : transcendents) {
        ImGui::PushID(transcendent.transcendentId.c_str());
        if (ImGui::Selectable(transcendent.name.c_str(), s_selectedTranscendentId == transcendent.transcendentId)) {
            s_selectedTranscendentId = transcendent.transcendentId;
        }
        if (s_selectedTranscendentId == transcendent.transcendentId) {
            ImGui::Text("Transcendence: %.2f | Holiness: %.2f | Elevation: %.2f | Ascension: %.2f",
                transcendent.transcendence, transcendent.holiness, transcendent.elevation, transcendent.ascension);
        }
        ImGui::PopID();
    }
}

void HolyEternityPanel::RenderGraceHolyTab() {
    ImGui::Text("Grace Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Grace", &s_graceHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessGraceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Mercy", &s_mercyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Bestow Grace")) {
        std::string graceId = HolyEternity::HolyEternityEngine::CreateGraceHoly(s_nameBuffer);
        HolyEternity::HolyEternityEngine::ShowMercy(graceId, s_mercyInput);
        HolyEternity::HolyEternityEngine::GrantFavor(graceId, s_favorInput);
        OnGraceBestowed(graceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Bestowed Graces:");
    auto graces = HolyEternity::HolyEternityEngine::GetAllGraceHolies();
    for (const auto& grace : graces) {
        ImGui::PushID(grace.graceId.c_str());
        if (ImGui::Selectable(grace.name.c_str(), s_selectedGraceId == grace.graceId)) {
            s_selectedGraceId = grace.graceId;
        }
        if (s_selectedGraceId == grace.graceId) {
            ImGui::Text("Grace: %.2f | Holiness: %.2f | Mercy: %.2f | Favor: %.2f",
                grace.grace, grace.holiness, grace.mercy, grace.favor);
        }
        ImGui::PopID();
    }
}

void HolyEternityPanel::RenderHolyMetricsTab() {
    ImGui::Text("Holy Eternity Metrics");
    ImGui::Separator();
    
    auto metrics = HolyEternity::HolyEternityEngine::GetHolyEternityMetrics();
    
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Text("Eternity Count: %d", metrics["eternityCount"].get<int>());
    ImGui::Text("Divine Count: %d", metrics["divineCount"].get<int>());
    ImGui::Text("Transcendent Count: %d", metrics["transcendentCount"].get<int>());
    ImGui::Text("Grace Count: %d", metrics["graceCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Holiness: %.4f", metrics["totalHoliness"].get<float>());
    ImGui::Text("Average Holiness: %.4f", metrics["averageHoliness"].get<float>());
    ImGui::Text("Holy Holies: %d", metrics["holyHolies"].get<int>());
    ImGui::Text("Total Eternity: %.4f", metrics["totalEternity"].get<float>());
    ImGui::Text("Eternal Holies: %d", metrics["eternalHolies"].get<int>());
    ImGui::Text("Divine Holies: %d", metrics["divineHolies"].get<int>());
    ImGui::Text("Transcendent Holies: %d", metrics["transcendentHolies"].get<int>());
    ImGui::Text("Graced Holies: %d", metrics["gracedHolies"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", HolyEternity::HolyEternityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Holy Report")) {
        auto report = HolyEternity::HolyEternityEngine::GenerateHolyEternityReport();
        // Export logic would go here
    }
}

void HolyEternityPanel::RenderHolyVisualizationTab() {
    ImGui::Text("Holy Eternity Visualization");
    ImGui::Separator();
    
    // Draw a representation of holy eternity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 15, 40, 255));
    
    // Draw holy structures as radiant orbs
    auto structures = HolyEternity::HolyEternityEngine::GetAllHolyEternityStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.holiness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.divinity * 10.0f;
        
        // Holy glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 220, 255, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 240, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw eternity holies as eternal rays
    auto eternities = HolyEternity::HolyEternityEngine::GetAllEternityHolies();
    int eternityIdx = 0;
    for (const auto& eternity : eternities) {
        float angle = (eternityIdx * 2.0f * 3.14159f) / std::max(1, (int)eternities.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + eternity.infinity * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = eternity.isEternal ? 
            IM_COL32(100, 255, 200, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + eternity.eternity * 3.0f);
        eternityIdx++;
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
