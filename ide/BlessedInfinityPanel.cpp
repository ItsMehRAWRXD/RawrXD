#include "ide/BlessedInfinityPanel.hpp"
#include "blessed/BlessedInfinityEngine.hpp"
#include "blessed/BlessedInfinityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool BlessedInfinityPanel::s_visible = false;
bool BlessedInfinityPanel::s_initialized = false;
int BlessedInfinityPanel::s_selectedTab = 0;
char BlessedInfinityPanel::s_nameBuffer[256] = {};
char BlessedInfinityPanel::s_entityIdBuffer[256] = {};
char BlessedInfinityPanel::s_attributeKeyBuffer[256] = {};
char BlessedInfinityPanel::s_attributeValueBuffer[512] = {};
float BlessedInfinityPanel::s_blessednessInput = 0.1f;
float BlessedInfinityPanel::s_infinityInput = 0.1f;
float BlessedInfinityPanel::s_abundanceInput = 0.1f;
float BlessedInfinityPanel::s_prosperityInput = 0.1f;
float BlessedInfinityPanel::s_graceInput = 0.1f;
float BlessedInfinityPanel::s_infinityBlessedInput = 0.1f;
float BlessedInfinityPanel::s_blessednessInfinityInput = 0.1f;
float BlessedInfinityPanel::s_endlessnessInput = 0.1f;
float BlessedInfinityPanel::s_boundlessnessInput = 0.1f;
float BlessedInfinityPanel::s_abundantBlessedInput = 0.1f;
float BlessedInfinityPanel::s_blessednessAbundantInput = 0.1f;
float BlessedInfinityPanel::s_plentyInput = 0.1f;
float BlessedInfinityPanel::s_wealthInput = 0.1f;
float BlessedInfinityPanel::s_prosperousBlessedInput = 0.1f;
float BlessedInfinityPanel::s_blessednessProsperousInput = 0.1f;
float BlessedInfinityPanel::s_successInput = 0.1f;
float BlessedInfinityPanel::s_flourishingInput = 0.1f;
float BlessedInfinityPanel::s_graceBlessedInput = 0.1f;
float BlessedInfinityPanel::s_blessednessGraceInput = 0.1f;
float BlessedInfinityPanel::s_mercyInput = 0.1f;
float BlessedInfinityPanel::s_favorInput = 0.1f;
std::string BlessedInfinityPanel::s_selectedBlessedId;
std::string BlessedInfinityPanel::s_selectedInfinityId;
std::string BlessedInfinityPanel::s_selectedAbundantId;
std::string BlessedInfinityPanel::s_selectedProsperousId;
std::string BlessedInfinityPanel::s_selectedGraceId;
std::vector<nlohmann::json> BlessedInfinityPanel::s_blessedEvents;

void BlessedInfinityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    BlessedInfinity::BlessedInfinityEngine::Init();
    BlessedInfinity::BlessedInfinityLoop::Init();
    BlessedInfinity::BlessedInfinityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void BlessedInfinityPanel::Shutdown() {
    if (!s_initialized) return;
    BlessedInfinity::BlessedInfinityLoop::Shutdown();
    BlessedInfinity::BlessedInfinityEngine::Shutdown();
    s_initialized = false;
}

void BlessedInfinityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Blessed Infinity Panel", &s_visible);
    
    const char* tabs[] = {
        "Blessed Structure", "Infinity Blessed", "Abundant Blessed",
        "Prosperous Blessed", "Grace Blessed", "Blessed Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("BlessedTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderBlessedStructureTab(); break;
                    case 1: RenderInfinityBlessedTab(); break;
                    case 2: RenderAbundantBlessedTab(); break;
                    case 3: RenderProsperousBlessedTab(); break;
                    case 4: RenderGraceBlessedTab(); break;
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

bool BlessedInfinityPanel::IsVisible() {
    return s_visible;
}

void BlessedInfinityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !BlessedInfinity::BlessedInfinityLoop::IsRunning()) {
        BlessedInfinity::BlessedInfinityLoop::Start();
    }
}

void BlessedInfinityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* BlessedInfinityPanel::GetPanelName() {
    return "Blessed Infinity";
}

void BlessedInfinityPanel::OnBlessedStructureCreated(const std::string& blessedId) {
    nlohmann::json event;
    event["type"] = "blessed_structure_created";
    event["blessedId"] = blessedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedInfinityPanel::OnInfinityEstablished(const std::string& infinityId) {
    nlohmann::json event;
    event["type"] = "infinity_established";
    event["infinityId"] = infinityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedInfinityPanel::OnAbundanceManifested(const std::string& abundantId) {
    nlohmann::json event;
    event["type"] = "abundance_manifested";
    event["abundantId"] = abundantId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedInfinityPanel::OnProsperityRealized(const std::string& prosperousId) {
    nlohmann::json event;
    event["type"] = "prosperity_realized";
    event["prosperousId"] = prosperousId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedInfinityPanel::OnGraceBestowed(const std::string& graceId) {
    nlohmann::json event;
    event["type"] = "grace_bestowed";
    event["graceId"] = graceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedInfinityPanel::RenderBlessedStructureTab() {
    ImGui::Text("Blessed Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Abundance", &s_abundanceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Prosperity", &s_prosperityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string blessedId = BlessedInfinity::BlessedInfinityEngine::CreateBlessedInfinityStructure(s_nameBuffer);
        BlessedInfinity::BlessedInfinityEngine::AmplifyBlessedness(blessedId, s_blessednessInput);
        BlessedInfinity::BlessedInfinityEngine::ExpandInfinity(blessedId, s_infinityInput);
        BlessedInfinity::BlessedInfinityEngine::IncreaseAbundance(blessedId, s_abundanceInput);
        BlessedInfinity::BlessedInfinityEngine::EnhanceProsperity(blessedId, s_prosperityInput);
        BlessedInfinity::BlessedInfinityEngine::BestowGrace(blessedId, s_graceInput);
        OnBlessedStructureCreated(blessedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = BlessedInfinity::BlessedInfinityEngine::GetAllBlessedInfinityStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.blessedId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedBlessedId == structure.blessedId)) {
            s_selectedBlessedId = structure.blessedId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nBlessedness: %.2f\nInfinity: %.2f\nAbundance: %.2f\nProsperity: %.2f\nGrace: %.2f",
                structure.blessedId.c_str(), structure.blessedness, structure.infinity, 
                structure.abundance, structure.prosperity, structure.grace);
        }
        ImGui::PopID();
    }
}

void BlessedInfinityPanel::RenderInfinityBlessedTab() {
    ImGui::Text("Infinity Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Infinity", &s_infinityBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessInfinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Endlessness", &s_endlessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Boundlessness", &s_boundlessnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Infinity")) {
        std::string infinityId = BlessedInfinity::BlessedInfinityEngine::CreateInfinityBlessed(s_nameBuffer);
        BlessedInfinity::BlessedInfinityEngine::PerpetuateInfinity(infinityId, s_infinityBlessedInput);
        BlessedInfinity::BlessedInfinityEngine::ExpandBoundlessness(infinityId, s_boundlessnessInput);
        OnInfinityEstablished(infinityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Infinities:");
    auto infinities = BlessedInfinity::BlessedInfinityEngine::GetAllInfinityBlesseds();
    for (const auto& infinity : infinities) {
        ImGui::PushID(infinity.infinityId.c_str());
        bool isSelected = s_selectedInfinityId == infinity.infinityId;
        if (ImGui::Selectable(infinity.name.c_str(), isSelected)) {
            s_selectedInfinityId = infinity.infinityId;
        }
        ImGui::SameLine();
        if (infinity.isInfinite) {
            ImGui::TextColored(ImVec4(0.8f, 1, 0.2f, 1), "[INFINITE]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[FINITE]");
        }
        if (s_selectedInfinityId == infinity.infinityId) {
            if (!infinity.isInfinite && ImGui::Button("Declare Infinite")) {
                BlessedInfinity::BlessedInfinityEngine::DeclareInfinite(infinity.infinityId);
            }
        }
        ImGui::PopID();
    }
}

void BlessedInfinityPanel::RenderAbundantBlessedTab() {
    ImGui::Text("Abundant Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Abundance", &s_abundantBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessAbundantInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Plenty", &s_plentyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Wealth", &s_wealthInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Abundance")) {
        std::string abundantId = BlessedInfinity::BlessedInfinityEngine::CreateAbundantBlessed(s_nameBuffer);
        BlessedInfinity::BlessedInfinityEngine::MultiplyAbundance(abundantId, s_abundantBlessedInput);
        BlessedInfinity::BlessedInfinityEngine::IncreasePlenty(abundantId, s_plentyInput);
        OnAbundanceManifested(abundantId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Abundances:");
    auto abundants = BlessedInfinity::BlessedInfinityEngine::GetAllAbundantBlesseds();
    for (const auto& abundant : abundants) {
        ImGui::PushID(abundant.abundantId.c_str());
        if (ImGui::Selectable(abundant.name.c_str(), s_selectedAbundantId == abundant.abundantId)) {
            s_selectedAbundantId = abundant.abundantId;
        }
        if (s_selectedAbundantId == abundant.abundantId) {
            ImGui::Text("Abundance: %.2f | Blessedness: %.2f | Plenty: %.2f | Wealth: %.2f",
                abundant.abundance, abundant.blessedness, abundant.plenty, abundant.wealth);
        }
        ImGui::PopID();
    }
}

void BlessedInfinityPanel::RenderProsperousBlessedTab() {
    ImGui::Text("Prosperous Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Prosperity", &s_prosperousBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessProsperousInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Success", &s_successInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Flourishing", &s_flourishingInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Prosperity")) {
        std::string prosperousId = BlessedInfinity::BlessedInfinityEngine::CreateProsperousBlessed(s_nameBuffer);
        BlessedInfinity::BlessedInfinityEngine::CultivateSuccess(prosperousId, s_successInput);
        BlessedInfinity::BlessedInfinityEngine::NurtureFlourishing(prosperousId, s_flourishingInput);
        OnProsperityRealized(prosperousId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Prosperities:");
    auto prosperouss = BlessedInfinity::BlessedInfinityEngine::GetAllProsperousBlesseds();
    for (const auto& prosperous : prosperouss) {
        ImGui::PushID(prosperous.prosperousId.c_str());
        if (ImGui::Selectable(prosperous.name.c_str(), s_selectedProsperousId == prosperous.prosperousId)) {
            s_selectedProsperousId = prosperous.prosperousId;
        }
        if (s_selectedProsperousId == prosperous.prosperousId) {
            ImGui::Text("Prosperity: %.2f | Blessedness: %.2f | Success: %.2f | Flourishing: %.2f",
                prosperous.prosperity, prosperous.blessedness, prosperous.success, prosperous.flourishing);
        }
        ImGui::PopID();
    }
}

void BlessedInfinityPanel::RenderGraceBlessedTab() {
    ImGui::Text("Grace Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Grace", &s_graceBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessGraceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Mercy", &s_mercyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Bestow Grace")) {
        std::string graceId = BlessedInfinity::BlessedInfinityEngine::CreateGraceBlessed(s_nameBuffer);
        BlessedInfinity::BlessedInfinityEngine::ShowMercy(graceId, s_mercyInput);
        BlessedInfinity::BlessedInfinityEngine::GrantFavor(graceId, s_favorInput);
        OnGraceBestowed(graceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Bestowed Graces:");
    auto graces = BlessedInfinity::BlessedInfinityEngine::GetAllGraceBlesseds();
    for (const auto& grace : graces) {
        ImGui::PushID(grace.graceId.c_str());
        if (ImGui::Selectable(grace.name.c_str(), s_selectedGraceId == grace.graceId)) {
            s_selectedGraceId = grace.graceId;
        }
        if (s_selectedGraceId == grace.graceId) {
            ImGui::Text("Grace: %.2f | Blessedness: %.2f | Mercy: %.2f | Favor: %.2f",
                grace.grace, grace.blessedness, grace.mercy, grace.favor);
        }
        ImGui::PopID();
    }
}

void BlessedInfinityPanel::RenderBlessedMetricsTab() {
    ImGui::Text("Blessed Infinity Metrics");
    ImGui::Separator();
    
    auto metrics = BlessedInfinity::BlessedInfinityEngine::GetBlessedInfinityMetrics();
    
    ImGui::Text("Blessed Count: %d", metrics["blessedCount"].get<int>());
    ImGui::Text("Infinity Count: %d", metrics["infinityCount"].get<int>());
    ImGui::Text("Abundant Count: %d", metrics["abundantCount"].get<int>());
    ImGui::Text("Prosperous Count: %d", metrics["prosperousCount"].get<int>());
    ImGui::Text("Grace Count: %d", metrics["graceCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Blessedness: %.4f", metrics["totalBlessedness"].get<float>());
    ImGui::Text("Average Blessedness: %.4f", metrics["averageBlessedness"].get<float>());
    ImGui::Text("Blessed Blesseds: %d", metrics["blessedBlesseds"].get<int>());
    ImGui::Text("Total Infinity: %.4f", metrics["totalInfinity"].get<float>());
    ImGui::Text("Infinite Blesseds: %d", metrics["infiniteBlesseds"].get<int>());
    ImGui::Text("Abundant Blesseds: %d", metrics["abundantBlesseds"].get<int>());
    ImGui::Text("Prosperous Blesseds: %d", metrics["prosperousBlesseds"].get<int>());
    ImGui::Text("Graced Blesseds: %d", metrics["gracedBlesseds"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", BlessedInfinity::BlessedInfinityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Blessed Report")) {
        auto report = BlessedInfinity::BlessedInfinityEngine::GenerateBlessedInfinityReport();
        // Export logic would go here
    }
}

void BlessedInfinityPanel::RenderBlessedVisualizationTab() {
    ImGui::Text("Blessed Infinity Visualization");
    ImGui::Separator();
    
    // Draw a representation of blessed infinity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(25, 20, 35, 255));
    
    // Draw blessed structures as radiant orbs
    auto structures = BlessedInfinity::BlessedInfinityEngine::GetAllBlessedInfinityStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.blessedness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.abundance * 10.0f;
        
        // Blessed glow effect
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(255, 220, 150, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 240, 200, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw infinity blesseds as infinite rays
    auto infinities = BlessedInfinity::BlessedInfinityEngine::GetAllInfinityBlesseds();
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
            IM_COL32(200, 255, 100, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + infinity.infinity * 3.0f);
        infinityIdx++;
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
