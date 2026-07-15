#include "ide/HolyInfinityPanel.hpp"
#include "holy/HolyInfinityEngine.hpp"
#include "holy/HolyInfinityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool HolyInfinityPanel::s_visible = false;
bool HolyInfinityPanel::s_initialized = false;
int HolyInfinityPanel::s_selectedTab = 0;
char HolyInfinityPanel::s_nameBuffer[256] = {};
char HolyInfinityPanel::s_entityIdBuffer[256] = {};
char HolyInfinityPanel::s_attributeKeyBuffer[256] = {};
char HolyInfinityPanel::s_attributeValueBuffer[512] = {};
float HolyInfinityPanel::s_holinessInput = 0.1f;
float HolyInfinityPanel::s_infinityInput = 0.1f;
float HolyInfinityPanel::s_graceInput = 0.1f;
float HolyInfinityPanel::s_mercyInput = 0.1f;
float HolyInfinityPanel::s_blessingInput = 0.1f;
float HolyInfinityPanel::s_infinityHolyInput = 0.1f;
float HolyInfinityPanel::s_holinessInfinityInput = 0.1f;
float HolyInfinityPanel::s_boundlessnessInput = 0.1f;
float HolyInfinityPanel::s_endlessnessInput = 0.1f;
float HolyInfinityPanel::s_graceHolyInput = 0.1f;
float HolyInfinityPanel::s_holinessGraceInput = 0.1f;
float HolyInfinityPanel::s_favorInput = 0.1f;
float HolyInfinityPanel::s_benevolenceInput = 0.1f;
float HolyInfinityPanel::s_mercyHolyInput = 0.1f;
float HolyInfinityPanel::s_holinessMercyInput = 0.1f;
float HolyInfinityPanel::s_compassionInput = 0.1f;
float HolyInfinityPanel::s_forgivenessInput = 0.1f;
float HolyInfinityPanel::s_blessingHolyInput = 0.1f;
float HolyInfinityPanel::s_holinessBlessingInput = 0.1f;
float HolyInfinityPanel::s_abundanceInput = 0.1f;
float HolyInfinityPanel::s_prosperityInput = 0.1f;
std::string HolyInfinityPanel::s_selectedHolyId;
std::string HolyInfinityPanel::s_selectedInfinityId;
std::string HolyInfinityPanel::s_selectedGraceId;
std::string HolyInfinityPanel::s_selectedMercyId;
std::string HolyInfinityPanel::s_selectedBlessingId;
std::vector<nlohmann::json> HolyInfinityPanel::s_holyEvents;

void HolyInfinityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    HolyInfinity::HolyInfinityEngine::Init();
    HolyInfinity::HolyInfinityLoop::Init();
    HolyInfinity::HolyInfinityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void HolyInfinityPanel::Shutdown() {
    if (!s_initialized) return;
    HolyInfinity::HolyInfinityLoop::Shutdown();
    HolyInfinity::HolyInfinityEngine::Shutdown();
    s_initialized = false;
}

void HolyInfinityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Holy Infinity Panel", &s_visible);
    
    const char* tabs[] = {
        "Holy Structure", "Infinity Holy", "Grace Holy",
        "Mercy Holy", "Blessing Holy", "Holy Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("HolyTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderHolyStructureTab(); break;
                    case 1: RenderInfinityHolyTab(); break;
                    case 2: RenderGraceHolyTab(); break;
                    case 3: RenderMercyHolyTab(); break;
                    case 4: RenderBlessingHolyTab(); break;
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

bool HolyInfinityPanel::IsVisible() {
    return s_visible;
}

void HolyInfinityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !HolyInfinity::HolyInfinityLoop::IsRunning()) {
        HolyInfinity::HolyInfinityLoop::Start();
    }
}

void HolyInfinityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* HolyInfinityPanel::GetPanelName() {
    return "Holy Infinity";
}

void HolyInfinityPanel::OnHolyStructureCreated(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_structure_created";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyInfinityPanel::OnInfinityEstablished(const std::string& infinityId) {
    nlohmann::json event;
    event["type"] = "infinity_established";
    event["infinityId"] = infinityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyInfinityPanel::OnGraceBestowed(const std::string& graceId) {
    nlohmann::json event;
    event["type"] = "grace_bestowed";
    event["graceId"] = graceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyInfinityPanel::OnMercyShown(const std::string& mercyId) {
    nlohmann::json event;
    event["type"] = "mercy_shown";
    event["mercyId"] = mercyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyInfinityPanel::OnBlessingGranted(const std::string& blessingId) {
    nlohmann::json event;
    event["type"] = "blessing_granted";
    event["blessingId"] = blessingId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolyInfinityPanel::RenderHolyStructureTab() {
    ImGui::Text("Holy Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Mercy", &s_mercyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessing", &s_blessingInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string holyId = HolyInfinity::HolyInfinityEngine::CreateHolyInfinityStructure(s_nameBuffer);
        HolyInfinity::HolyInfinityEngine::ElevateHoliness(holyId, s_holinessInput);
        HolyInfinity::HolyInfinityEngine::ExpandInfinity(holyId, s_infinityInput);
        HolyInfinity::HolyInfinityEngine::BestowGrace(holyId, s_graceInput);
        HolyInfinity::HolyInfinityEngine::ShowMercy(holyId, s_mercyInput);
        HolyInfinity::HolyInfinityEngine::GrantBlessing(holyId, s_blessingInput);
        OnHolyStructureCreated(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = HolyInfinity::HolyInfinityEngine::GetAllHolyInfinityStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.holyId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedHolyId == structure.holyId)) {
            s_selectedHolyId = structure.holyId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nHoliness: %.2f\nInfinity: %.2f\nGrace: %.2f\nMercy: %.2f\nBlessing: %.2f",
                structure.holyId.c_str(), structure.holiness, structure.infinity, 
                structure.grace, structure.mercy, structure.blessing);
        }
        ImGui::PopID();
    }
}

void HolyInfinityPanel::RenderInfinityHolyTab() {
    ImGui::Text("Infinity Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Infinity", &s_infinityHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessInfinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Boundlessness", &s_boundlessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Endlessness", &s_endlessnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Infinity")) {
        std::string infinityId = HolyInfinity::HolyInfinityEngine::CreateInfinityHoly(s_nameBuffer);
        HolyInfinity::HolyInfinityEngine::PerpetuateInfinity(infinityId, s_infinityHolyInput);
        HolyInfinity::HolyInfinityEngine::ExpandBoundlessness(infinityId, s_boundlessnessInput);
        OnInfinityEstablished(infinityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Infinities:");
    auto infinities = HolyInfinity::HolyInfinityEngine::GetAllInfinityHolies();
    for (const auto& infinity : infinities) {
        ImGui::PushID(infinity.infinityId.c_str());
        bool isSelected = s_selectedInfinityId == infinity.infinityId;
        if (ImGui::Selectable(infinity.name.c_str(), isSelected)) {
            s_selectedInfinityId = infinity.infinityId;
        }
        ImGui::SameLine();
        if (infinity.isInfinite) {
            ImGui::TextColored(ImVec4(0.5f, 1, 0.8f, 1), "[INFINITE]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[FINITE]");
        }
        if (s_selectedInfinityId == infinity.infinityId) {
            if (!infinity.isInfinite && ImGui::Button("Declare Infinite")) {
                HolyInfinity::HolyInfinityEngine::DeclareInfinite(infinity.infinityId);
            }
        }
        ImGui::PopID();
    }
}

void HolyInfinityPanel::RenderGraceHolyTab() {
    ImGui::Text("Grace Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Grace", &s_graceHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessGraceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Benevolence", &s_benevolenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Bestow Grace")) {
        std::string graceId = HolyInfinity::HolyInfinityEngine::CreateGraceHoly(s_nameBuffer);
        HolyInfinity::HolyInfinityEngine::IncreaseFavor(graceId, s_favorInput);
        HolyInfinity::HolyInfinityEngine::DeepenBenevolence(graceId, s_benevolenceInput);
        OnGraceBestowed(graceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Bestowed Graces:");
    auto graces = HolyInfinity::HolyInfinityEngine::GetAllGraceHolies();
    for (const auto& grace : graces) {
        ImGui::PushID(grace.graceId.c_str());
        if (ImGui::Selectable(grace.name.c_str(), s_selectedGraceId == grace.graceId)) {
            s_selectedGraceId = grace.graceId;
        }
        if (s_selectedGraceId == grace.graceId) {
            ImGui::Text("Grace: %.2f | Holiness: %.2f | Favor: %.2f | Benevolence: %.2f",
                grace.grace, grace.holiness, grace.favor, grace.benevolence);
        }
        ImGui::PopID();
    }
}

void HolyInfinityPanel::RenderMercyHolyTab() {
    ImGui::Text("Mercy Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Mercy", &s_mercyHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessMercyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Compassion", &s_compassionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Forgiveness", &s_forgivenessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Show Mercy")) {
        std::string mercyId = HolyInfinity::HolyInfinityEngine::CreateMercyHoly(s_nameBuffer);
        HolyInfinity::HolyInfinityEngine::ExpandCompassion(mercyId, s_compassionInput);
        HolyInfinity::HolyInfinityEngine::GrantForgiveness(mercyId, s_forgivenessInput);
        OnMercyShown(mercyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Shown Mercies:");
    auto mercies = HolyInfinity::HolyInfinityEngine::GetAllMercyHolies();
    for (const auto& mercy : mercies) {
        ImGui::PushID(mercy.mercyId.c_str());
        if (ImGui::Selectable(mercy.name.c_str(), s_selectedMercyId == mercy.mercyId)) {
            s_selectedMercyId = mercy.mercyId;
        }
        if (s_selectedMercyId == mercy.mercyId) {
            ImGui::Text("Mercy: %.2f | Holiness: %.2f | Compassion: %.2f | Forgiveness: %.2f",
                mercy.mercy, mercy.holiness, mercy.compassion, mercy.forgiveness);
        }
        ImGui::PopID();
    }
}

void HolyInfinityPanel::RenderBlessingHolyTab() {
    ImGui::Text("Blessing Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessing", &s_blessingHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessBlessingInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Abundance", &s_abundanceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Prosperity", &s_prosperityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Grant Blessing")) {
        std::string blessingId = HolyInfinity::HolyInfinityEngine::CreateBlessingHoly(s_nameBuffer);
        HolyInfinity::HolyInfinityEngine::MultiplyAbundance(blessingId, s_abundanceInput);
        HolyInfinity::HolyInfinityEngine::EnhanceProsperity(blessingId, s_prosperityInput);
        OnBlessingGranted(blessingId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Granted Blessings:");
    auto blessings = HolyInfinity::HolyInfinityEngine::GetAllBlessingHolies();
    for (const auto& blessing : blessings) {
        ImGui::PushID(blessing.blessingId.c_str());
        if (ImGui::Selectable(blessing.name.c_str(), s_selectedBlessingId == blessing.blessingId)) {
            s_selectedBlessingId = blessing.blessingId;
        }
        if (s_selectedBlessingId == blessing.blessingId) {
            ImGui::Text("Blessing: %.2f | Holiness: %.2f | Abundance: %.2f | Prosperity: %.2f",
                blessing.blessing, blessing.holiness, blessing.abundance, blessing.prosperity);
        }
        ImGui::PopID();
    }
}

void HolyInfinityPanel::RenderHolyMetricsTab() {
    ImGui::Text("Holy Infinity Metrics");
    ImGui::Separator();
    
    auto metrics = HolyInfinity::HolyInfinityEngine::GetHolyInfinityMetrics();
    
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Text("Infinity Count: %d", metrics["infinityCount"].get<int>());
    ImGui::Text("Grace Count: %d", metrics["graceCount"].get<int>());
    ImGui::Text("Mercy Count: %d", metrics["mercyCount"].get<int>());
    ImGui::Text("Blessing Count: %d", metrics["blessingCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Holiness: %.4f", metrics["totalHoliness"].get<float>());
    ImGui::Text("Average Holiness: %.4f", metrics["averageHoliness"].get<float>());
    ImGui::Text("Holy Holies: %d", metrics["holyHolies"].get<int>());
    ImGui::Text("Total Infinity: %.4f", metrics["totalInfinity"].get<float>());
    ImGui::Text("Infinite Holies: %d", metrics["infiniteHolies"].get<int>());
    ImGui::Text("Graced Holies: %d", metrics["gracedHolies"].get<int>());
    ImGui::Text("Merciful Holies: %d", metrics["mercifulHolies"].get<int>());
    ImGui::Text("Blessed Holies: %d", metrics["blessedHolies"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", HolyInfinity::HolyInfinityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Holy Report")) {
        auto report = HolyInfinity::HolyInfinityEngine::GenerateHolyInfinityReport();
        // Export logic would go here
    }
}

void HolyInfinityPanel::RenderHolyVisualizationTab() {
    ImGui::Text("Holy Infinity Visualization");
    ImGui::Separator();
    
    // Draw a representation of holy infinity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 25, 40, 255));
    
    // Draw holy structures as radiant orbs
    auto structures = HolyInfinity::HolyInfinityEngine::GetAllHolyInfinityStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.holiness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.grace * 10.0f;
        
        // Holy glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 255, 220, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 255, 240, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw infinity holies as infinite rays
    auto infinities = HolyInfinity::HolyInfinityEngine::GetAllInfinityHolies();
    int infinityIdx = 0;
    for (const auto& infinity : infinities) {
        float angle = (infinityIdx * 2.0f * 3.14159f) / std::max(1, (int)infinities.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + infinity.boundlessness * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = infinity.isInfinite ? 
            IM_COL32(150, 255, 200, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + infinity.infinity * 3.0f);
        infinityIdx++;
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
