#include "ide/DivineEternityPanel.hpp"
#include "divine/DivineEternityEngine.hpp"
#include "divine/DivineEternityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool DivineEternityPanel::s_visible = false;
bool DivineEternityPanel::s_initialized = false;
int DivineEternityPanel::s_selectedTab = 0;
char DivineEternityPanel::s_nameBuffer[256] = {};
char DivineEternityPanel::s_entityIdBuffer[256] = {};
char DivineEternityPanel::s_attributeKeyBuffer[256] = {};
char DivineEternityPanel::s_attributeValueBuffer[512] = {};
float DivineEternityPanel::s_divinityInput = 0.1f;
float DivineEternityPanel::s_eternalityInput = 0.1f;
float DivineEternityPanel::s_sanctityInput = 0.1f;
float DivineEternityPanel::s_sacrednessInput = 0.1f;
float DivineEternityPanel::s_perpetuityInput = 0.1f;
float DivineEternityPanel::s_holinessInput = 0.1f;
float DivineEternityPanel::s_holinessEternalInput = 0.1f;
float DivineEternityPanel::s_divinityEternalInput = 0.1f;
float DivineEternityPanel::s_graceInput = 0.1f;
float DivineEternityPanel::s_blessednessInput = 0.1f;
float DivineEternityPanel::s_eternalityBlessedInput = 0.1f;
float DivineEternityPanel::s_divinityBlessedInput = 0.1f;
float DivineEternityPanel::s_sanctificationInput = 0.1f;
float DivineEternityPanel::s_eternalitySanctifiedInput = 0.1f;
float DivineEternityPanel::s_divinitySanctifiedInput = 0.1f;
std::string DivineEternityPanel::s_selectedStructureId;
std::string DivineEternityPanel::s_selectedEternityId;
std::string DivineEternityPanel::s_selectedEternalId;
std::string DivineEternityPanel::s_selectedBlessedId;
std::string DivineEternityPanel::s_selectedSanctifiedId;
std::vector<nlohmann::json> DivineEternityPanel::s_divineEvents;

void DivineEternityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Divine::DivineEternityEngine::Init();
    Divine::DivineEternityLoop::Init();
    Divine::DivineEternityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void DivineEternityPanel::Shutdown() {
    if (!s_initialized) return;
    Divine::DivineEternityLoop::Shutdown();
    Divine::DivineEternityEngine::Shutdown();
    s_initialized = false;
}

void DivineEternityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Divine Eternity Panel", &s_visible);
    
    const char* tabs[] = {
        "Divine Structure", "Sacred Eternity", "Holy Eternal",
        "Blessed Eternity", "Sanctified Eternal", "Divine Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("DivineTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderDivineStructureTab(); break;
                    case 1: RenderSacredEternityTab(); break;
                    case 2: RenderHolyEternalTab(); break;
                    case 3: RenderBlessedEternityTab(); break;
                    case 4: RenderSanctifiedEternalTab(); break;
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

bool DivineEternityPanel::IsVisible() {
    return s_visible;
}

void DivineEternityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Divine::DivineEternityLoop::IsRunning()) {
        Divine::DivineEternityLoop::Start();
    }
}

void DivineEternityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* DivineEternityPanel::GetPanelName() {
    return "Divine Eternity";
}

void DivineEternityPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineEternityPanel::OnEternityEstablished(const std::string& eternityId) {
    nlohmann::json event;
    event["type"] = "eternity_established";
    event["eternityId"] = eternityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineEternityPanel::OnEternalManifested(const std::string& eternalId) {
    nlohmann::json event;
    event["type"] = "eternal_manifested";
    event["eternalId"] = eternalId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineEternityPanel::OnBlessedRealized(const std::string& blessedId) {
    nlohmann::json event;
    event["type"] = "blessed_realized";
    event["blessedId"] = blessedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineEternityPanel::OnSanctifiedDiscovered(const std::string& sanctifiedId) {
    nlohmann::json event;
    event["type"] = "sanctified_discovered";
    event["sanctifiedId"] = sanctifiedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineEternityPanel::RenderDivineStructureTab() {
    ImGui::Text("Divine Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternality", &s_eternalityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctity", &s_sanctityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Divine::DivineEternityEngine::CreateDivineStructure(s_nameBuffer);
        Divine::DivineEternityEngine::ExpandDivinity(structureId, s_divinityInput);
        Divine::DivineEternityEngine::DeepenEternality(structureId, s_eternalityInput);
        Divine::DivineEternityEngine::IncreaseSanctity(structureId, s_sanctityInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Divine::DivineEternityEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.structureId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.structureId)) {
            s_selectedStructureId = structure.structureId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nDivinity: %.2f\nEternality: %.2f\nSanctity: %.2f",
                structure.structureId.c_str(), structure.divinity, structure.eternality, structure.sanctity);
        }
        ImGui::PopID();
    }
}

void DivineEternityPanel::RenderSacredEternityTab() {
    ImGui::Text("Sacred Eternity Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sacredness", &s_sacrednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Eternity")) {
        std::string eternityId = Divine::DivineEternityEngine::EstablishSacredEternity(s_nameBuffer);
        Divine::DivineEternityEngine::IncreaseSacredness(eternityId, s_sacrednessInput);
        Divine::DivineEternityEngine::ExtendPerpetuity(eternityId, s_perpetuityInput);
        Divine::DivineEternityEngine::ElevateHoliness(eternityId, s_holinessInput);
        OnEternityEstablished(eternityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Eternities:");
    auto eternities = Divine::DivineEternityEngine::GetAllEternities();
    for (const auto& eternity : eternities) {
        ImGui::PushID(eternity.eternityId.c_str());
        bool isSelected = s_selectedEternityId == eternity.eternityId;
        if (ImGui::Selectable(eternity.name.c_str(), isSelected)) {
            s_selectedEternityId = eternity.eternityId;
        }
        ImGui::SameLine();
        if (eternity.isSacred) {
            ImGui::TextColored(ImVec4(1, 0.8, 0, 1), "[SACRED]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[STANDARD]");
        }
        if (s_selectedEternityId == eternity.eternityId) {
            if (!eternity.isSacred && ImGui::Button("Declare Sacred")) {
                Divine::DivineEternityEngine::DeclareSacred(eternity.eternityId);
            }
        }
        ImGui::PopID();
    }
}

void DivineEternityPanel::RenderHolyEternalTab() {
    ImGui::Text("Holy Eternal Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessEternalInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinityEternalInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Eternal")) {
        std::string eternalId = Divine::DivineEternityEngine::ManifestHolyEternal(s_nameBuffer);
        Divine::DivineEternityEngine::ElevateHoliness(eternalId, s_holinessEternalInput);
        Divine::DivineEternityEngine::ExpandDivinity(eternalId, s_divinityEternalInput);
        Divine::DivineEternityEngine::BestowGrace(eternalId, s_graceInput);
        OnEternalManifested(eternalId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Eternals:");
    auto eternals = Divine::DivineEternityEngine::GetAllEternals();
    for (const auto& eternal : eternals) {
        ImGui::PushID(eternal.eternalId.c_str());
        if (ImGui::Selectable(eternal.name.c_str(), s_selectedEternalId == eternal.eternalId)) {
            s_selectedEternalId = eternal.eternalId;
        }
        if (s_selectedEternalId == eternal.eternalId) {
            ImGui::Text("Holiness: %.2f | Divinity: %.2f | Grace: %.2f",
                eternal.holiness, eternal.divinity, eternal.grace);
            ImGui::Text("Holy Entities: %zu", eternal.holyEntities.size());
        }
        ImGui::PopID();
    }
}

void DivineEternityPanel::RenderBlessedEternityTab() {
    ImGui::Text("Blessed Eternity Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternality", &s_eternalityBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinityBlessedInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Blessed")) {
        std::string blessedId = Divine::DivineEternityEngine::RealizeBlessedEternity(s_nameBuffer);
        Divine::DivineEternityEngine::AmplifyBlessedness(blessedId, s_blessednessInput);
        Divine::DivineEternityEngine::DeepenEternality(blessedId, s_eternalityBlessedInput);
        Divine::DivineEternityEngine::ExpandDivinity(blessedId, s_divinityBlessedInput);
        OnBlessedRealized(blessedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Blessed:");
    auto blessed = Divine::DivineEternityEngine::GetAllBlessed();
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
            ImGui::Text("Blessedness: %.2f | Eternality: %.2f | Divinity: %.2f",
                b.blessedness, b.eternality, b.divinity);
            if (!b.isBlessed && ImGui::Button("Declare Blessed")) {
                Divine::DivineEternityEngine::DeclareBlessed(b.blessedId);
            }
        }
        ImGui::PopID();
    }
}

void DivineEternityPanel::RenderSanctifiedEternalTab() {
    ImGui::Text("Sanctified Eternal Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Sanctification", &s_sanctificationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternality", &s_eternalitySanctifiedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinitySanctifiedInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Sanctified")) {
        std::string sanctifiedId = Divine::DivineEternityEngine::DiscoverSanctifiedEternal(s_nameBuffer);
        Divine::DivineEternityEngine::IncreaseSanctification(sanctifiedId, s_sanctificationInput);
        Divine::DivineEternityEngine::DeepenEternality(sanctifiedId, s_eternalitySanctifiedInput);
        Divine::DivineEternityEngine::ExpandDivinity(sanctifiedId, s_divinitySanctifiedInput);
        OnSanctifiedDiscovered(sanctifiedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Sanctified:");
    auto sanctified = Divine::DivineEternityEngine::GetAllSanctified();
    for (const auto& s : sanctified) {
        ImGui::PushID(s.sanctifiedId.c_str());
        if (ImGui::Selectable(s.name.c_str(), s_selectedSanctifiedId == s.sanctifiedId)) {
            s_selectedSanctifiedId = s.sanctifiedId;
        }
        if (s_selectedSanctifiedId == s.sanctifiedId) {
            ImGui::Text("Sanctification: %.2f | Eternality: %.2f | Divinity: %.2f",
                s.sanctification, s.eternality, s.divinity);
            ImGui::Text("Sanctified Entities: %zu", s.sanctifiedEntities.size());
        }
        ImGui::PopID();
    }
}

void DivineEternityPanel::RenderDivineMetricsTab() {
    ImGui::Text("Divine Metrics");
    ImGui::Separator();
    
    auto metrics = Divine::DivineEternityEngine::GetDivineMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Eternity Count: %d", metrics["eternityCount"].get<int>());
    ImGui::Text("Eternal Count: %d", metrics["eternalCount"].get<int>());
    ImGui::Text("Blessed Count: %d", metrics["blessedCount"].get<int>());
    ImGui::Text("Sanctified Count: %d", metrics["sanctifiedCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Divinity: %.4f", metrics["totalDivinity"].get<float>());
    ImGui::Text("Average Sacredness: %.4f", metrics["averageSacredness"].get<float>());
    ImGui::Text("Sacred Eternities: %d", metrics["sacredEternities"].get<int>());
    ImGui::Text("Blessed Eternities: %d", metrics["blessedEternities"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Divine::DivineEternityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Divine Report")) {
        auto report = Divine::DivineEternityEngine::GenerateDivineReport();
        // Export logic would go here
    }
}

void DivineEternityPanel::RenderDivineVisualizationTab() {
    ImGui::Text("Divine Visualization");
    ImGui::Separator();
    
    // Draw a representation of divine eternity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(10, 5, 25, 255));
    
    // Draw divine structures as golden orbs
    auto structures = Divine::DivineEternityEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 70.0f + structure.divinity * 60.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 8.0f + structure.sanctity * 12.0f;
        
        // Divine glow effect
        for (int i = 5; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 5, IM_COL32(255, 215, 0, 40 - i * 7), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 223, 100, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 30, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw holy eternals as radiant beams
    auto eternals = Divine::DivineEternityEngine::GetAllEternals();
    int eternalIdx = 0;
    for (const auto& eternal : eternals) {
        float angle = (eternalIdx * 2.0f * 3.14159f) / std::max(1, (int)eternals.size()) + ImGui::GetTime() * 0.5f;
        float innerRadius = 20.0f;
        float outerRadius = 100.0f + eternal.grace * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = IM_COL32(255, 255, 200, 100 + eternal.holiness * 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + eternal.divinity * 3.0f);
        eternalIdx++;
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
