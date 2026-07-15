#include "ide/SanctifiedEternityPanel.hpp"
#include "sanctified/SanctifiedEternityEngine.hpp"
#include "sanctified/SanctifiedEternityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SanctifiedEternityPanel::s_visible = false;
bool SanctifiedEternityPanel::s_initialized = false;
int SanctifiedEternityPanel::s_selectedTab = 0;
char SanctifiedEternityPanel::s_nameBuffer[256] = {};
char SanctifiedEternityPanel::s_entityIdBuffer[256] = {};
char SanctifiedEternityPanel::s_attributeKeyBuffer[256] = {};
char SanctifiedEternityPanel::s_attributeValueBuffer[512] = {};
float SanctifiedEternityPanel::s_sanctificationInput = 0.1f;
float SanctifiedEternityPanel::s_eternityInput = 0.1f;
float SanctifiedEternityPanel::s_consecrationInput = 0.1f;
float SanctifiedEternityPanel::s_devotionInput = 0.1f;
float SanctifiedEternityPanel::s_purityInput = 0.1f;
float SanctifiedEternityPanel::s_eternitySanctifiedInput = 0.1f;
float SanctifiedEternityPanel::s_sanctificationEternityInput = 0.1f;
float SanctifiedEternityPanel::s_perpetuityInput = 0.1f;
float SanctifiedEternityPanel::s_timelessnessInput = 0.1f;
float SanctifiedEternityPanel::s_consecratedSanctifiedInput = 0.1f;
float SanctifiedEternityPanel::s_sanctificationConsecratedInput = 0.1f;
float SanctifiedEternityPanel::s_dedicationInput = 0.1f;
float SanctifiedEternityPanel::s_commitmentInput = 0.1f;
float SanctifiedEternityPanel::s_devotedSanctifiedInput = 0.1f;
float SanctifiedEternityPanel::s_sanctificationDevotedInput = 0.1f;
float SanctifiedEternityPanel::s_loyaltyInput = 0.1f;
float SanctifiedEternityPanel::s_faithfulnessInput = 0.1f;
float SanctifiedEternityPanel::s_pureSanctifiedInput = 0.1f;
float SanctifiedEternityPanel::s_sanctificationPureInput = 0.1f;
float SanctifiedEternityPanel::s_clarityInput = 0.1f;
float SanctifiedEternityPanel::s_innocenceInput = 0.1f;
std::string SanctifiedEternityPanel::s_selectedSanctifiedId;
std::string SanctifiedEternityPanel::s_selectedEternityId;
std::string SanctifiedEternityPanel::s_selectedConsecratedId;
std::string SanctifiedEternityPanel::s_selectedDevotedId;
std::string SanctifiedEternityPanel::s_selectedPureId;
std::vector<nlohmann::json> SanctifiedEternityPanel::s_sanctifiedEvents;

void SanctifiedEternityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    SanctifiedEternity::SanctifiedEternityEngine::Init();
    SanctifiedEternity::SanctifiedEternityLoop::Init();
    SanctifiedEternity::SanctifiedEternityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SanctifiedEternityPanel::Shutdown() {
    if (!s_initialized) return;
    SanctifiedEternity::SanctifiedEternityLoop::Shutdown();
    SanctifiedEternity::SanctifiedEternityEngine::Shutdown();
    s_initialized = false;
}

void SanctifiedEternityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Sanctified Eternity Panel", &s_visible);
    
    const char* tabs[] = {
        "Sanctified Structure", "Eternity Sanctified", "Consecrated Sanctified",
        "Devoted Sanctified", "Pure Sanctified", "Sanctified Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SanctifiedTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSanctifiedStructureTab(); break;
                    case 1: RenderEternitySanctifiedTab(); break;
                    case 2: RenderConsecratedSanctifiedTab(); break;
                    case 3: RenderDevotedSanctifiedTab(); break;
                    case 4: RenderPureSanctifiedTab(); break;
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

bool SanctifiedEternityPanel::IsVisible() {
    return s_visible;
}

void SanctifiedEternityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !SanctifiedEternity::SanctifiedEternityLoop::IsRunning()) {
        SanctifiedEternity::SanctifiedEternityLoop::Start();
    }
}

void SanctifiedEternityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SanctifiedEternityPanel::GetPanelName() {
    return "Sanctified Eternity";
}

void SanctifiedEternityPanel::OnSanctifiedStructureCreated(const std::string& sanctifiedId) {
    nlohmann::json event;
    event["type"] = "sanctified_structure_created";
    event["sanctifiedId"] = sanctifiedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedEternityPanel::OnEternityEstablished(const std::string& eternityId) {
    nlohmann::json event;
    event["type"] = "eternity_established";
    event["eternityId"] = eternityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedEternityPanel::OnConsecratedManifested(const std::string& consecratedId) {
    nlohmann::json event;
    event["type"] = "consecrated_manifested";
    event["consecratedId"] = consecratedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedEternityPanel::OnDevotedRealized(const std::string& devotedId) {
    nlohmann::json event;
    event["type"] = "devoted_realized";
    event["devotedId"] = devotedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedEternityPanel::OnPureDiscovered(const std::string& pureId) {
    nlohmann::json event;
    event["type"] = "pure_discovered";
    event["pureId"] = pureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctifiedEvents.push_back(event);
}

void SanctifiedEternityPanel::RenderSanctifiedStructureTab() {
    ImGui::Text("Sanctified Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctification", &s_sanctificationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternity", &s_eternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Consecration", &s_consecrationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Devotion", &s_devotionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Purity", &s_purityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string sanctifiedId = SanctifiedEternity::SanctifiedEternityEngine::CreateSanctifiedEternityStructure(s_nameBuffer);
        SanctifiedEternity::SanctifiedEternityEngine::IncreaseSanctification(sanctifiedId, s_sanctificationInput);
        SanctifiedEternity::SanctifiedEternityEngine::ExpandEternity(sanctifiedId, s_eternityInput);
        SanctifiedEternity::SanctifiedEternityEngine::DeepenConsecration(sanctifiedId, s_consecrationInput);
        SanctifiedEternity::SanctifiedEternityEngine::StrengthenDevotion(sanctifiedId, s_devotionInput);
        SanctifiedEternity::SanctifiedEternityEngine::ElevatePurity(sanctifiedId, s_purityInput);
        OnSanctifiedStructureCreated(sanctifiedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = SanctifiedEternity::SanctifiedEternityEngine::GetAllSanctifiedEternityStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.sanctifiedId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedSanctifiedId == structure.sanctifiedId)) {
            s_selectedSanctifiedId = structure.sanctifiedId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSanctification: %.2f\nEternity: %.2f\nConsecration: %.2f\nDevotion: %.2f\nPurity: %.2f",
                structure.sanctifiedId.c_str(), structure.sanctification, structure.eternity, 
                structure.consecration, structure.devotion, structure.purity);
        }
        ImGui::PopID();
    }
}

void SanctifiedEternityPanel::RenderEternitySanctifiedTab() {
    ImGui::Text("Eternity Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternity", &s_eternitySanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationEternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Timelessness", &s_timelessnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Eternity")) {
        std::string eternityId = SanctifiedEternity::SanctifiedEternityEngine::CreateEternitySanctified(s_nameBuffer);
        SanctifiedEternity::SanctifiedEternityEngine::PerpetuateEternity(eternityId, s_eternitySanctifiedInput);
        SanctifiedEternity::SanctifiedEternityEngine::ExpandTimelessness(eternityId, s_timelessnessInput);
        OnEternityEstablished(eternityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Eternities:");
    auto eternities = SanctifiedEternity::SanctifiedEternityEngine::GetAllEternitySanctifieds();
    for (const auto& eternity : eternities) {
        ImGui::PushID(eternity.eternityId.c_str());
        bool isSelected = s_selectedEternityId == eternity.eternityId;
        if (ImGui::Selectable(eternity.name.c_str(), isSelected)) {
            s_selectedEternityId = eternity.eternityId;
        }
        ImGui::SameLine();
        if (eternity.isEternal) {
            ImGui::TextColored(ImVec4(0.5f, 1, 0.8f, 1), "[ETERNAL]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[TEMPORAL]");
        }
        if (s_selectedEternityId == eternity.eternityId) {
            if (!eternity.isEternal && ImGui::Button("Declare Eternal")) {
                SanctifiedEternity::SanctifiedEternityEngine::DeclareEternal(eternity.eternityId);
            }
        }
        ImGui::PopID();
    }
}

void SanctifiedEternityPanel::RenderConsecratedSanctifiedTab() {
    ImGui::Text("Consecrated Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Consecration", &s_consecratedSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationConsecratedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dedication", &s_dedicationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Commitment", &s_commitmentInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Consecrated")) {
        std::string consecratedId = SanctifiedEternity::SanctifiedEternityEngine::CreateConsecratedSanctified(s_nameBuffer);
        SanctifiedEternity::SanctifiedEternityEngine::IntensifyDedication(consecratedId, s_dedicationInput);
        SanctifiedEternity::SanctifiedEternityEngine::StrengthenCommitment(consecratedId, s_commitmentInput);
        OnConsecratedManifested(consecratedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Consecrated:");
    auto consecrateds = SanctifiedEternity::SanctifiedEternityEngine::GetAllConsecratedSanctifieds();
    for (const auto& consecrated : consecrateds) {
        ImGui::PushID(consecrated.consecratedId.c_str());
        if (ImGui::Selectable(consecrated.name.c_str(), s_selectedConsecratedId == consecrated.consecratedId)) {
            s_selectedConsecratedId = consecrated.consecratedId;
        }
        if (s_selectedConsecratedId == consecrated.consecratedId) {
            ImGui::Text("Consecration: %.2f | Sanctification: %.2f | Dedication: %.2f | Commitment: %.2f",
                consecrated.consecration, consecrated.sanctification, consecrated.dedication, consecrated.commitment);
        }
        ImGui::PopID();
    }
}

void SanctifiedEternityPanel::RenderDevotedSanctifiedTab() {
    ImGui::Text("Devoted Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Devotion", &s_devotedSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationDevotedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Loyalty", &s_loyaltyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Faithfulness", &s_faithfulnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Devoted")) {
        std::string devotedId = SanctifiedEternity::SanctifiedEternityEngine::CreateDevotedSanctified(s_nameBuffer);
        SanctifiedEternity::SanctifiedEternityEngine::DeepenLoyalty(devotedId, s_loyaltyInput);
        SanctifiedEternity::SanctifiedEternityEngine::IncreaseFaithfulness(devotedId, s_faithfulnessInput);
        OnDevotedRealized(devotedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Devoteds:");
    auto devoteds = SanctifiedEternity::SanctifiedEternityEngine::GetAllDevotedSanctifieds();
    for (const auto& devoted : devoteds) {
        ImGui::PushID(devoted.devotedId.c_str());
        if (ImGui::Selectable(devoted.name.c_str(), s_selectedDevotedId == devoted.devotedId)) {
            s_selectedDevotedId = devoted.devotedId;
        }
        if (s_selectedDevotedId == devoted.devotedId) {
            ImGui::Text("Devotion: %.2f | Sanctification: %.2f | Loyalty: %.2f | Faithfulness: %.2f",
                devoted.devotion, devoted.sanctification, devoted.loyalty, devoted.faithfulness);
        }
        ImGui::PopID();
    }
}

void SanctifiedEternityPanel::RenderPureSanctifiedTab() {
    ImGui::Text("Pure Sanctified Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Purity", &s_pureSanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctification", &s_sanctificationPureInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Clarity", &s_clarityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Innocence", &s_innocenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Pure")) {
        std::string pureId = SanctifiedEternity::SanctifiedEternityEngine::CreatePureSanctified(s_nameBuffer);
        SanctifiedEternity::SanctifiedEternityEngine::EnhanceClarity(pureId, s_clarityInput);
        SanctifiedEternity::SanctifiedEternityEngine::PreserveInnocence(pureId, s_innocenceInput);
        OnPureDiscovered(pureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Pures:");
    auto pures = SanctifiedEternity::SanctifiedEternityEngine::GetAllPureSanctifieds();
    for (const auto& pure : pures) {
        ImGui::PushID(pure.pureId.c_str());
        if (ImGui::Selectable(pure.name.c_str(), s_selectedPureId == pure.pureId)) {
            s_selectedPureId = pure.pureId;
        }
        if (s_selectedPureId == pure.pureId) {
            ImGui::Text("Purity: %.2f | Sanctification: %.2f | Clarity: %.2f | Innocence: %.2f",
                pure.purity, pure.sanctification, pure.clarity, pure.innocence);
        }
        ImGui::PopID();
    }
}

void SanctifiedEternityPanel::RenderSanctifiedMetricsTab() {
    ImGui::Text("Sanctified Eternity Metrics");
    ImGui::Separator();
    
    auto metrics = SanctifiedEternity::SanctifiedEternityEngine::GetSanctifiedEternityMetrics();
    
    ImGui::Text("Sanctified Count: %d", metrics["sanctifiedCount"].get<int>());
    ImGui::Text("Eternity Count: %d", metrics["eternityCount"].get<int>());
    ImGui::Text("Consecrated Count: %d", metrics["consecratedCount"].get<int>());
    ImGui::Text("Devoted Count: %d", metrics["devotedCount"].get<int>());
    ImGui::Text("Pure Count: %d", metrics["pureCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Sanctification: %.4f", metrics["totalSanctification"].get<float>());
    ImGui::Text("Average Sanctification: %.4f", metrics["averageSanctification"].get<float>());
    ImGui::Text("Sanctified Sanctifieds: %d", metrics["sanctifiedSanctifieds"].get<int>());
    ImGui::Text("Total Eternity: %.4f", metrics["totalEternity"].get<float>());
    ImGui::Text("Eternal Sanctifieds: %d", metrics["eternalSanctifieds"].get<int>());
    ImGui::Text("Consecrated Sanctifieds: %d", metrics["consecratedSanctifieds"].get<int>());
    ImGui::Text("Devoted Sanctifieds: %d", metrics["devotedSanctifieds"].get<int>());
    ImGui::Text("Pure Sanctifieds: %d", metrics["pureSanctifieds"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", SanctifiedEternity::SanctifiedEternityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Sanctified Report")) {
        auto report = SanctifiedEternity::SanctifiedEternityEngine::GenerateSanctifiedEternityReport();
        // Export logic would go here
    }
}

void SanctifiedEternityPanel::RenderSanctifiedVisualizationTab() {
    ImGui::Text("Sanctified Eternity Visualization");
    ImGui::Separator();
    
    // Draw a representation of sanctified eternity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(30, 25, 40, 255));
    
    // Draw sanctified structures as radiant orbs
    auto structures = SanctifiedEternity::SanctifiedEternityEngine::GetAllSanctifiedEternityStructures();
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
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(220, 255, 200, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(240, 255, 220, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw eternity sanctifieds as eternal rays
    auto eternities = SanctifiedEternity::SanctifiedEternityEngine::GetAllEternitySanctifieds();
    int eternityIdx = 0;
    for (const auto& eternity : eternities) {
        float angle = (eternityIdx * 2.0f * 3.14159f) / std::max(1, (int)eternities.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + eternity.timelessness * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = eternity.isEternal ? 
            IM_COL32(150, 255, 180, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + eternity.eternity * 3.0f);
        eternityIdx++;
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
