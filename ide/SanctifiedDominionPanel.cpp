#include "ide/SanctifiedDominionPanel.hpp"
#include "sanctified/SanctifiedDominionEngine.hpp"
#include "sanctified/SanctifiedDominionLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SanctifiedDominionPanel::s_visible = false;
bool SanctifiedDominionPanel::s_initialized = false;
int SanctifiedDominionPanel::s_selectedTab = 0;
char SanctifiedDominionPanel::s_nameBuffer[256] = {};
char SanctifiedDominionPanel::s_entityIdBuffer[256] = {};
char SanctifiedDominionPanel::s_attributeKeyBuffer[256] = {};
char SanctifiedDominionPanel::s_attributeValueBuffer[512] = {};
float SanctifiedDominionPanel::s_sanctifiednessInput = 0.1f;
float SanctifiedDominionPanel::s_dominionInput = 0.1f;
float SanctifiedDominionPanel::s_purityInput = 0.1f;
float SanctifiedDominionPanel::s_devotionInput = 0.1f;
float SanctifiedDominionPanel::s_consecrationInput = 0.1f;
float SanctifiedDominionPanel::s_dominionSanctifiedInput = 0.1f;
float SanctifiedDominionPanel::s_sanctifiednessDominionInput = 0.1f;
float SanctifiedDominionPanel::s_authorityInput = 0.1f;
float SanctifiedDominionPanel::s_ruleInput = 0.1f;
float SanctifiedDominionPanel::s_puritySanctifiedInput = 0.1f;
float SanctifiedDominionPanel::s_sanctifiednessPurityInput = 0.1f;
float SanctifiedDominionPanel::s_cleanlinessInput = 0.1f;
float SanctifiedDominionPanel::s_innocenceInput = 0.1f;
float SanctifiedDominionPanel::s_devotionSanctifiedInput = 0.1f;
float SanctifiedDominionPanel::s_sanctifiednessDevotionInput = 0.1f;
float SanctifiedDominionPanel::s_dedicationInput = 0.1f;
float SanctifiedDominionPanel::s_commitmentInput = 0.1f;
float SanctifiedDominionPanel::s_consecrationSanctifiedInput = 0.1f;
float SanctifiedDominionPanel::s_sanctifiednessConsecrationInput = 0.1f;
float SanctifiedDominionPanel::s_dedicationConsecrationInput = 0.1f;
float SanctifiedDominionPanel::s_sanctityInput = 0.1f;
std::string SanctifiedDominionPanel::s_selectedSanctifiedId;
std::string SanctifiedDominionPanel::s_selectedDominionId;
std::string SanctifiedDominionPanel::s_selectedPurityId;
std::string SanctifiedDominionPanel::s_selectedDevotionId;
std::string SanctifiedDominionPanel::s_selectedConsecrationId;
std::vector<nlohmann::json> SanctifiedDominionPanel::s_sanctifiedEvents;

void SanctifiedDominionPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    SanctifiedDominion::SanctifiedDominionEngine::Init();
    SanctifiedDominion::SanctifiedDominionLoop::Init();
    SanctifiedDominion::SanctifiedDominionLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SanctifiedDominionPanel::Shutdown() {
    if (!s_initialized) return;
    SanctifiedDominion::SanctifiedDominionLoop::Shutdown();
    SanctifiedDominion::SanctifiedDominionEngine::Shutdown();
    s_initialized = false;
}

void SanctifiedDominionPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sanctified Dominion Panel", &s_visible);
    
    const char* tabs[] = {
        "Sanctified Structure", "Dominion Sanctified", "Purity Sanctified",
        "Devotion Sanctified", "Consecration Sanctified", "Sanctified Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SanctifiedTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSanctifiedStructureTab(); break;
                    case 1: RenderDominionSanctifiedTab(); break;
                    case 2: RenderPuritySanctifiedTab(); break;
                    case 3: RenderDevotionSanctifiedTab(); break;
                    case 4: RenderConsecrationSanctifiedTab(); break;
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

bool SanctifiedDominionPanel::IsVisible() {
    return s_visible;
}

void SanctifiedDominionPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !SanctifiedDominion::SanctifiedDominionLoop::IsRunning()) {
        SanctifiedDominion::SanctifiedDominionLoop::Start();
    }
}

void SanctifiedDominionPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SanctifiedDominionPanel::GetPanelName() {
    return "Sanctified Dominion";
}

void SanctifiedDominionPanel::OnSanctifiedStructureCreated(const std::string& sanctifiedId) {
    nlohmann::json event;
    event["type"] = "sanctified_structure_created";
    event["sanctifiedId"] = sanctifiedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedDominionPanel::OnDominionEstablished(const std::string& dominionId) {
    nlohmann::json event;
    event["type"] = "dominion_established";
    event["dominionId"] = dominionId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedDominionPanel::OnPurityBestowed(const std::string& purityId) {
    nlohmann::json event;
    event["type"] = "purity_bestowed";
    event["purityId"] = purityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedDominionPanel::OnDevotionInspired(const std::string& devotionId) {
    nlohmann::json event;
    event["type"] = "devotion_inspired";
    event["devotionId"] = devotionId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedDominionPanel::OnConsecrationPerformed(const std::string& consecrationId) {
    nlohmann::json event;
    event["type"] = "consecration_performed";
    event["consecrationId"] = consecrationId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedDominionPanel::RenderSanctifiedStructureTab() {
    ImGui::Text("Sanctified Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctifiedness", &s_sanctifiednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Purity", &s_purityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Devotion", &s_devotionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string sanctifiedId = SanctifiedDominion::SanctifiedDominionEngine::CreateSanctifiedDominionStructure(s_nameBuffer);
        SanctifiedDominion::SanctifiedDominionEngine::ElevateSanctifiedness(sanctifiedId, s_sanctifiednessInput);
        SanctifiedDominion::SanctifiedDominionEngine::ExpandDominion(sanctifiedId, s_dominionInput);
        SanctifiedDominion::SanctifiedDominionEngine::BestowPurity(sanctifiedId, s_purityInput);
        SanctifiedDominion::SanctifiedDominionEngine::InspireDevotion(sanctifiedId, s_devotionInput);
        SanctifiedDominion::SanctifiedDominionEngine::PerformConsecration(sanctifiedId, s_consecrationInput);
        OnSanctifiedStructureCreated(sanctifiedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = SanctifiedDominion::SanctifiedDominionEngine::GetAllSanctifiedDominionStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.sanctifiedId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedSanctifiedId == structure.sanctifiedId)) {
            s_selectedSanctifiedId = structure.sanctifiedId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSanctifiedness: %.2f\nDominion: %.2f\nPurity: %.2f\nDevotion: %.2f\nConsecration: %.2f",
                structure.sanctifiedId.c_str(), structure.sanctifiedness, structure.dominion, 
                structure.purity, structure.devotion, structure.consecration);
        }
        ImGui::PopID();
    }
}

void SanctifiedDominionPanel::RenderDominionSanctifiedTab() {
    ImGui::Text("Dominion Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Dominion", &s_dominionSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctifiedness", &s_sanctifiednessDominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Rule", &s_ruleInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Dominion")) {
        std::string dominionId = SanctifiedDominion::SanctifiedDominionEngine::CreateDominionSanctified(s_nameBuffer);
        SanctifiedDominion::SanctifiedDominionEngine::AssertAuthority(dominionId, s_authorityInput);
        SanctifiedDominion::SanctifiedDominionEngine::EstablishRule(dominionId, s_ruleInput);
        OnDominionEstablished(dominionId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Dominions:");
    auto dominions = SanctifiedDominion::SanctifiedDominionEngine::GetAllDominionSanctifieds();
    for (const auto& dominion : dominions) {
        ImGui::PushID(dominion.dominionId.c_str());
        bool isSelected = s_selectedDominionId == dominion.dominionId;
        if (ImGui::Selectable(dominion.name.c_str(), isSelected)) {
            s_selectedDominionId = dominion.dominionId;
        }
        ImGui::SameLine();
        if (dominion.isSupreme) {
            ImGui::TextColored(ImVec4(0.8f, 0.5f, 1.0f, 1), "[SUPREME]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[ORDINARY]");
        }
        if (s_selectedDominionId == dominion.dominionId) {
            if (!dominion.isSupreme && ImGui::Button("Declare Supreme")) {
                SanctifiedDominion::SanctifiedDominionEngine::DeclareSupreme(dominion.dominionId);
            }
        }
        ImGui::PopID();
    }
}

void SanctifiedDominionPanel::RenderPuritySanctifiedTab() {
    ImGui::Text("Purity Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Purity", &s_puritySanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctifiedness", &s_sanctifiednessPurityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Cleanliness", &s_cleanlinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Innocence", &s_innocenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Bestow Purity")) {
        std::string purityId = SanctifiedDominion::SanctifiedDominionEngine::CreatePuritySanctified(s_nameBuffer);
        SanctifiedDominion::SanctifiedDominionEngine::Purify(purityId, s_cleanlinessInput);
        SanctifiedDominion::SanctifiedDominionEngine::RestoreInnocence(purityId, s_innocenceInput);
        OnPurityBestowed(purityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Bestowed Purities:");
    auto purities = SanctifiedDominion::SanctifiedDominionEngine::GetAllPuritySanctifieds();
    for (const auto& purity : purities) {
        ImGui::PushID(purity.purityId.c_str());
        if (ImGui::Selectable(purity.name.c_str(), s_selectedPurityId == purity.purityId)) {
            s_selectedPurityId = purity.purityId;
        }
        if (s_selectedPurityId == purity.purityId) {
            ImGui::Text("Purity: %.2f | Sanctifiedness: %.2f | Cleanliness: %.2f | Innocence: %.2f",
                purity.purity, purity.sanctifiedness, purity.cleanliness, purity.innocence);
        }
        ImGui::PopID();
    }
}

void SanctifiedDominionPanel::RenderDevotionSanctifiedTab() {
    ImGui::Text("Devotion Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Devotion", &s_devotionSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctifiedness", &s_sanctifiednessDevotionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dedication", &s_dedicationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Commitment", &s_commitmentInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Inspire Devotion")) {
        std::string devotionId = SanctifiedDominion::SanctifiedDominionEngine::CreateDevotionSanctified(s_nameBuffer);
        SanctifiedDominion::SanctifiedDominionEngine::DeepenDedication(devotionId, s_dedicationInput);
        SanctifiedDominion::SanctifiedDominionEngine::StrengthenCommitment(devotionId, s_commitmentInput);
        OnDevotionInspired(devotionId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Inspired Devotions:");
    auto devotions = SanctifiedDominion::SanctifiedDominionEngine::GetAllDevotionSanctifieds();
    for (const auto& devotion : devotions) {
        ImGui::PushID(devotion.devotionId.c_str());
        bool isSelected = s_selectedDevotionId == devotion.devotionId;
        if (ImGui::Selectable(devotion.name.c_str(), isSelected)) {
            s_selectedDevotionId = devotion.devotionId;
        }
        ImGui::SameLine();
        if (devotion.isDevoted) {
            ImGui::TextColored(ImVec4(1, 0.6f, 0.8f, 1), "[DEVOTED]");
        }
        if (s_selectedDevotionId == devotion.devotionId) {
            ImGui::Text("Devotion: %.2f | Sanctifiedness: %.2f | Dedication: %.2f | Commitment: %.2f",
                devotion.devotion, devotion.sanctifiedness, devotion.dedication, devotion.commitment);
            if (!devotion.isDevoted && ImGui::Button("Declare Devoted")) {
                SanctifiedDominion::SanctifiedDominionEngine::DeclareDevoted(devotion.devotionId);
            }
        }
        ImGui::PopID();
    }
}

void SanctifiedDominionPanel::RenderConsecrationSanctifiedTab() {
    ImGui::Text("Consecration Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Consecration", &s_consecrationSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctifiedness", &s_sanctifiednessConsecrationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dedication", &s_dedicationConsecrationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctity", &s_sanctityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Perform Consecration")) {
        std::string consecrationId = SanctifiedDominion::SanctifiedDominionEngine::CreateConsecrationSanctified(s_nameBuffer);
        SanctifiedDominion::SanctifiedDominionEngine::IntensifyDedication(consecrationId, s_dedicationConsecrationInput);
        SanctifiedDominion::SanctifiedDominionEngine::ElevateSanctity(consecrationId, s_sanctityInput);
        OnConsecrationPerformed(consecrationId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Performed Consecrations:");
    auto consecrations = SanctifiedDominion::SanctifiedDominionEngine::GetAllConsecrationSanctifieds();
    for (const auto& consecration : consecrations) {
        ImGui::PushID(consecration.consecrationId.c_str());
        if (ImGui::Selectable(consecration.name.c_str(), s_selectedConsecrationId == consecration.consecrationId)) {
            s_selectedConsecrationId = consecration.consecrationId;
        }
        if (s_selectedConsecrationId == consecration.consecrationId) {
            ImGui::Text("Consecration: %.2f | Sanctifiedness: %.2f | Dedication: %.2f | Sanctity: %.2f",
                consecration.consecration, consecration.sanctifiedness, consecration.dedication, consecration.sanctity);
        }
        ImGui::PopID();
    }
}

void SanctifiedDominionPanel::RenderSanctifiedMetricsTab() {
    ImGui::Text("Sanctified Dominion Metrics");
    ImGui::Separator();
    
    auto metrics = SanctifiedDominion::SanctifiedDominionEngine::GetSanctifiedDominionMetrics();
    
    ImGui::Text("Sanctified Count: %d", metrics["sanctifiedCount"].get<int>());
    ImGui::Text("Dominion Count: %d", metrics["dominionCount"].get<int>());
    ImGui::Text("Purity Count: %d", metrics["purityCount"].get<int>());
    ImGui::Text("Devotion Count: %d", metrics["devotionCount"].get<int>());
    ImGui::Text("Consecration Count: %d", metrics["consecrationCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Sanctifiedness: %.4f", metrics["totalSanctifiedness"].get<float>());
    ImGui::Text("Average Sanctifiedness: %.4f", metrics["averageSanctifiedness"].get<float>());
    ImGui::Text("Sanctified Sanctifieds: %d", metrics["sanctifiedSanctifieds"].get<int>());
    ImGui::Text("Total Dominion: %.4f", metrics["totalDominion"].get<float>());
    ImGui::Text("Supreme Dominions: %d", metrics["supremeDominions"].get<int>());
    ImGui::Text("Devoted Devotions: %d", metrics["devotedDevotions"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", SanctifiedDominion::SanctifiedDominionLoop::GetTickCount());
    ImGui::Text("Loop FPS: %.1f", SanctifiedDominion::SanctifiedDominionLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Sanctified Report")) {
        auto report = SanctifiedDominion::SanctifiedDominionEngine::GenerateSanctifiedDominionReport();
        // Export logic would go here
    }
}

void SanctifiedDominionPanel::RenderSanctifiedVisualizationTab() {
    ImGui::Text("Sanctified Dominion Visualization");
    ImGui::Separator();
    
    // Draw a representation of sanctified dominion
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 25, 40, 255));
    
    // Draw sanctified structures as violet orbs
    auto structures = SanctifiedDominion::SanctifiedDominionEngine::GetAllSanctifiedDominionStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.sanctifiedness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.purity * 10.0f;
        
        // Sanctified glow effect (violet)
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 150, 255, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 180, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw dominion sanctifieds as authority rays
    auto dominions = SanctifiedDominion::SanctifiedDominionEngine::GetAllDominionSanctifieds();
    int dominionIdx = 0;
    for (const auto& dominion : dominions) {
        float angle = (dominionIdx * 2.0f * 3.14159f) / std::max(1, (int)dominions.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + dominion.authority * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = dominion.isSupreme ? 
            IM_COL32(200, 150, 255, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + dominion.dominion * 3.0f);
        dominionIdx++;
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
