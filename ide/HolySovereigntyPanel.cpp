#include "ide/HolySovereigntyPanel.hpp"
#include "holy/HolySovereigntyEngine.hpp"
#include "holy/HolySovereigntyLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool HolySovereigntyPanel::s_visible = false;
bool HolySovereigntyPanel::s_initialized = false;
int HolySovereigntyPanel::s_selectedTab = 0;
char HolySovereigntyPanel::s_nameBuffer[256] = {};
char HolySovereigntyPanel::s_entityIdBuffer[256] = {};
char HolySovereigntyPanel::s_attributeKeyBuffer[256] = {};
char HolySovereigntyPanel::s_attributeValueBuffer[512] = {};
float HolySovereigntyPanel::s_holinessInput = 0.1f;
float HolySovereigntyPanel::s_sovereigntyInput = 0.1f;
float HolySovereigntyPanel::s_gloryInput = 0.1f;
float HolySovereigntyPanel::s_majestyInput = 0.1f;
float HolySovereigntyPanel::s_powerInput = 0.1f;
float HolySovereigntyPanel::s_sovereigntyHolyInput = 0.1f;
float HolySovereigntyPanel::s_holinessSovereigntyInput = 0.1f;
float HolySovereigntyPanel::s_supremacyInput = 0.1f;
float HolySovereigntyPanel::s_dominionInput = 0.1f;
float HolySovereigntyPanel::s_gloryHolyInput = 0.1f;
float HolySovereigntyPanel::s_holinessGloryInput = 0.1f;
float HolySovereigntyPanel::s_brillianceInput = 0.1f;
float HolySovereigntyPanel::s_splendorInput = 0.1f;
float HolySovereigntyPanel::s_majestyHolyInput = 0.1f;
float HolySovereigntyPanel::s_holinessMajestyInput = 0.1f;
float HolySovereigntyPanel::s_grandeurInput = 0.1f;
float HolySovereigntyPanel::s_dignityInput = 0.1f;
float HolySovereigntyPanel::s_powerHolyInput = 0.1f;
float HolySovereigntyPanel::s_holinessPowerInput = 0.1f;
float HolySovereigntyPanel::s_strengthInput = 0.1f;
float HolySovereigntyPanel::s_mightInput = 0.1f;
std::string HolySovereigntyPanel::s_selectedHolyId;
std::string HolySovereigntyPanel::s_selectedSovereigntyId;
std::string HolySovereigntyPanel::s_selectedGloryId;
std::string HolySovereigntyPanel::s_selectedMajestyId;
std::string HolySovereigntyPanel::s_selectedPowerId;
std::vector<nlohmann::json> HolySovereigntyPanel::s_holyEvents;

void HolySovereigntyPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    HolySovereignty::HolySovereigntyEngine::Init();
    HolySovereignty::HolySovereigntyLoop::Init();
    HolySovereignty::HolySovereigntyLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void HolySovereigntyPanel::Shutdown() {
    if (!s_initialized) return;
    HolySovereignty::HolySovereigntyLoop::Shutdown();
    HolySovereignty::HolySovereigntyEngine::Shutdown();
    s_initialized = false;
}

void HolySovereigntyPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Holy Sovereignty Panel", &s_visible);
    
    const char* tabs[] = {
        "Holy Structure", "Sovereignty Holy", "Glory Holy",
        "Majesty Holy", "Power Holy", "Holy Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("HolyTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderHolyStructureTab(); break;
                    case 1: RenderSovereigntyHolyTab(); break;
                    case 2: RenderGloryHolyTab(); break;
                    case 3: RenderMajestyHolyTab(); break;
                    case 4: RenderPowerHolyTab(); break;
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

bool HolySovereigntyPanel::IsVisible() {
    return s_visible;
}

void HolySovereigntyPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !HolySovereignty::HolySovereigntyLoop::IsRunning()) {
        HolySovereignty::HolySovereigntyLoop::Start();
    }
}

void HolySovereigntyPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* HolySovereigntyPanel::GetPanelName() {
    return "Holy Sovereignty";
}

void HolySovereigntyPanel::OnHolyStructureCreated(const std::string& holyId) {
    nlohmann::json event;
    event["type"] = "holy_structure_created";
    event["holyId"] = holyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolySovereigntyPanel::OnSovereigntyEstablished(const std::string& sovereigntyId) {
    nlohmann::json event;
    event["type"] = "sovereignty_established";
    event["sovereigntyId"] = sovereigntyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolySovereigntyPanel::OnGloryBestowed(const std::string& gloryId) {
    nlohmann::json event;
    event["type"] = "glory_bestowed";
    event["gloryId"] = gloryId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolySovereigntyPanel::OnMajestyCrowned(const std::string& majestyId) {
    nlohmann::json event;
    event["type"] = "majesty_crowned";
    event["majestyId"] = majestyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolySovereigntyPanel::OnPowerChanneled(const std::string& powerId) {
    nlohmann::json event;
    event["type"] = "power_channeled";
    event["powerId"] = powerId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holyEvents.push_back(event);
}

void HolySovereigntyPanel::RenderHolyStructureTab() {
    ImGui::Text("Holy Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sovereignty", &s_sovereigntyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Glory", &s_gloryInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Majesty", &s_majestyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Power", &s_powerInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string holyId = HolySovereignty::HolySovereigntyEngine::CreateHolySovereigntyStructure(s_nameBuffer);
        HolySovereignty::HolySovereigntyEngine::ElevateHoliness(holyId, s_holinessInput);
        HolySovereignty::HolySovereigntyEngine::ExpandSovereignty(holyId, s_sovereigntyInput);
        HolySovereignty::HolySovereigntyEngine::BestowGlory(holyId, s_gloryInput);
        HolySovereignty::HolySovereigntyEngine::CrownMajesty(holyId, s_majestyInput);
        HolySovereignty::HolySovereigntyEngine::ChannelPower(holyId, s_powerInput);
        OnHolyStructureCreated(holyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = HolySovereignty::HolySovereigntyEngine::GetAllHolySovereigntyStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.holyId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedHolyId == structure.holyId)) {
            s_selectedHolyId = structure.holyId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nHoliness: %.2f\nSovereignty: %.2f\nGlory: %.2f\nMajesty: %.2f\nPower: %.2f",
                structure.holyId.c_str(), structure.holiness, structure.sovereignty, 
                structure.glory, structure.majesty, structure.power);
        }
        ImGui::PopID();
    }
}

void HolySovereigntyPanel::RenderSovereigntyHolyTab() {
    ImGui::Text("Sovereignty Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sovereignty", &s_sovereigntyHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessSovereigntyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Supremacy", &s_supremacyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Sovereignty")) {
        std::string sovereigntyId = HolySovereignty::HolySovereigntyEngine::CreateSovereigntyHoly(s_nameBuffer);
        HolySovereignty::HolySovereigntyEngine::AssertSupremacy(sovereigntyId, s_supremacyInput);
        HolySovereignty::HolySovereigntyEngine::ExtendDominion(sovereigntyId, s_dominionInput);
        OnSovereigntyEstablished(sovereigntyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Sovereignties:");
    auto sovereignties = HolySovereignty::HolySovereigntyEngine::GetAllSovereigntyHolies();
    for (const auto& sovereignty : sovereignties) {
        ImGui::PushID(sovereignty.sovereigntyId.c_str());
        bool isSelected = s_selectedSovereigntyId == sovereignty.sovereigntyId;
        if (ImGui::Selectable(sovereignty.name.c_str(), isSelected)) {
            s_selectedSovereigntyId = sovereignty.sovereigntyId;
        }
        ImGui::SameLine();
        if (sovereignty.isSupreme) {
            ImGui::TextColored(ImVec4(0.8f, 0.5f, 1.0f, 1), "[SUPREME]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[ORDINARY]");
        }
        if (s_selectedSovereigntyId == sovereignty.sovereigntyId) {
            if (!sovereignty.isSupreme && ImGui::Button("Declare Supreme")) {
                HolySovereignty::HolySovereigntyEngine::DeclareSupreme(sovereignty.sovereigntyId);
            }
        }
        ImGui::PopID();
    }
}

void HolySovereigntyPanel::RenderGloryHolyTab() {
    ImGui::Text("Glory Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Glory", &s_gloryHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessGloryInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Brilliance", &s_brillianceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Splendor", &s_splendorInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Bestow Glory")) {
        std::string gloryId = HolySovereignty::HolySovereigntyEngine::CreateGloryHoly(s_nameBuffer);
        HolySovereignty::HolySovereigntyEngine::RadiateBrilliance(gloryId, s_brillianceInput);
        HolySovereignty::HolySovereigntyEngine::ManifestSplendor(gloryId, s_splendorInput);
        OnGloryBestowed(gloryId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Bestowed Glories:");
    auto glories = HolySovereignty::HolySovereigntyEngine::GetAllGloryHolies();
    for (const auto& glory : glories) {
        ImGui::PushID(glory.gloryId.c_str());
        if (ImGui::Selectable(glory.name.c_str(), s_selectedGloryId == glory.gloryId)) {
            s_selectedGloryId = glory.gloryId;
        }
        if (s_selectedGloryId == glory.gloryId) {
            ImGui::Text("Glory: %.2f | Holiness: %.2f | Brilliance: %.2f | Splendor: %.2f",
                glory.glory, glory.holiness, glory.brilliance, glory.splendor);
        }
        ImGui::PopID();
    }
}

void HolySovereigntyPanel::RenderMajestyHolyTab() {
    ImGui::Text("Majesty Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Majesty", &s_majestyHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessMajestyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grandeur", &s_grandeurInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dignity", &s_dignityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Crown Majesty")) {
        std::string majestyId = HolySovereignty::HolySovereigntyEngine::CreateMajestyHoly(s_nameBuffer);
        HolySovereignty::HolySovereigntyEngine::ExaltGrandeur(majestyId, s_grandeurInput);
        HolySovereignty::HolySovereigntyEngine::UpholdDignity(majestyId, s_dignityInput);
        OnMajestyCrowned(majestyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Crowned Majesties:");
    auto majesties = HolySovereignty::HolySovereigntyEngine::GetAllMajestyHolies();
    for (const auto& majesty : majesties) {
        ImGui::PushID(majesty.majestyId.c_str());
        bool isSelected = s_selectedMajestyId == majesty.majestyId;
        if (ImGui::Selectable(majesty.name.c_str(), isSelected)) {
            s_selectedMajestyId = majesty.majestyId;
        }
        ImGui::SameLine();
        if (majesty.isMajestic) {
            ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "[MAJESTIC]");
        }
        if (s_selectedMajestyId == majesty.majestyId) {
            ImGui::Text("Majesty: %.2f | Holiness: %.2f | Grandeur: %.2f | Dignity: %.2f",
                majesty.majesty, majesty.holiness, majesty.grandeur, majesty.dignity);
            if (!majesty.isMajestic && ImGui::Button("Declare Majestic")) {
                HolySovereignty::HolySovereigntyEngine::DeclareMajestic(majesty.majestyId);
            }
        }
        ImGui::PopID();
    }
}

void HolySovereigntyPanel::RenderPowerHolyTab() {
    ImGui::Text("Power Holy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Power", &s_powerHolyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessPowerInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Strength", &s_strengthInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Might", &s_mightInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Channel Power")) {
        std::string powerId = HolySovereignty::HolySovereigntyEngine::CreatePowerHoly(s_nameBuffer);
        HolySovereignty::HolySovereigntyEngine::FortifyStrength(powerId, s_strengthInput);
        HolySovereignty::HolySovereigntyEngine::DemonstrateMight(powerId, s_mightInput);
        OnPowerChanneled(powerId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Channeled Powers:");
    auto powers = HolySovereignty::HolySovereigntyEngine::GetAllPowerHolies();
    for (const auto& power : powers) {
        ImGui::PushID(power.powerId.c_str());
        if (ImGui::Selectable(power.name.c_str(), s_selectedPowerId == power.powerId)) {
            s_selectedPowerId = power.powerId;
        }
        if (s_selectedPowerId == power.powerId) {
            ImGui::Text("Power: %.2f | Holiness: %.2f | Strength: %.2f | Might: %.2f",
                power.power, power.holiness, power.strength, power.might);
        }
        ImGui::PopID();
    }
}

void HolySovereigntyPanel::RenderHolyMetricsTab() {
    ImGui::Text("Holy Sovereignty Metrics");
    ImGui::Separator();
    
    auto metrics = HolySovereignty::HolySovereigntyEngine::GetHolySovereigntyMetrics();
    
    ImGui::Text("Holy Count: %d", metrics["holyCount"].get<int>());
    ImGui::Text("Sovereignty Count: %d", metrics["sovereigntyCount"].get<int>());
    ImGui::Text("Glory Count: %d", metrics["gloryCount"].get<int>());
    ImGui::Text("Majesty Count: %d", metrics["majestyCount"].get<int>());
    ImGui::Text("Power Count: %d", metrics["powerCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Holiness: %.4f", metrics["totalHoliness"].get<float>());
    ImGui::Text("Average Holiness: %.4f", metrics["averageHoliness"].get<float>());
    ImGui::Text("Holy Holies: %d", metrics["holyHolies"].get<int>());
    ImGui::Text("Total Sovereignty: %.4f", metrics["totalSovereignty"].get<float>());
    ImGui::Text("Supreme Sovereignties: %d", metrics["supremeSovereignties"].get<int>());
    ImGui::Text("Majestic Majesties: %d", metrics["majesticMajesties"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", HolySovereignty::HolySovereigntyLoop::GetTickCount());
    ImGui::Text("Loop FPS: %.1f", HolySovereignty::HolySovereigntyLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Holy Report")) {
        auto report = HolySovereignty::HolySovereigntyEngine::GenerateHolySovereigntyReport();
        // Export logic would go here
    }
}

void HolySovereigntyPanel::RenderHolyVisualizationTab() {
    ImGui::Text("Holy Sovereignty Visualization");
    ImGui::Separator();
    
    // Draw a representation of holy sovereignty
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 25, 40, 255));
    
    // Draw holy structures as radiant orbs
    auto structures = HolySovereignty::HolySovereigntyEngine::GetAllHolySovereigntyStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.holiness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.glory * 10.0f;
        
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
    
    // Draw sovereignty holies as supreme rays
    auto sovereignties = HolySovereignty::HolySovereigntyEngine::GetAllSovereigntyHolies();
    int sovereigntyIdx = 0;
    for (const auto& sovereignty : sovereignties) {
        float angle = (sovereigntyIdx * 2.0f * 3.14159f) / std::max(1, (int)sovereignties.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + sovereignty.supremacy * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = sovereignty.isSupreme ? 
            IM_COL32(200, 150, 255, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + sovereignty.sovereignty * 3.0f);
        sovereigntyIdx++;
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
