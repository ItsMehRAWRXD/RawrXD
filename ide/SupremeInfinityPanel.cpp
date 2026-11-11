#include "ide/SupremeInfinityPanel.hpp"
#include "supreme/SupremeInfinityEngine.hpp"
#include "supreme/SupremeInfinityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool SupremeInfinityPanel::s_visible = false;
bool SupremeInfinityPanel::s_initialized = false;
int SupremeInfinityPanel::s_selectedTab = 0;
char SupremeInfinityPanel::s_nameBuffer[256] = {};
char SupremeInfinityPanel::s_entityIdBuffer[256] = {};
char SupremeInfinityPanel::s_attributeKeyBuffer[256] = {};
char SupremeInfinityPanel::s_attributeValueBuffer[512] = {};
float SupremeInfinityPanel::s_supremacyInput = 0.1f;
float SupremeInfinityPanel::s_infinityInput = 0.1f;
float SupremeInfinityPanel::s_eternalityInput = 0.1f;
float SupremeInfinityPanel::s_ultimacyInput = 0.1f;
float SupremeInfinityPanel::s_boundlessnessInput = 0.1f;
float SupremeInfinityPanel::s_transcendenceInput = 0.1f;
float SupremeInfinityPanel::s_eternalitySupremacyInput = 0.1f;
float SupremeInfinityPanel::s_infinitySupremacyInput = 0.1f;
float SupremeInfinityPanel::s_divinityInput = 0.1f;
float SupremeInfinityPanel::s_infiniteSupremeInput = 0.1f;
float SupremeInfinityPanel::s_supremacyInfiniteInput = 0.1f;
float SupremeInfinityPanel::s_perpetuityInput = 0.1f;
float SupremeInfinityPanel::s_eternalitySupremeInput = 0.1f;
float SupremeInfinityPanel::s_supremacyEternalInput = 0.1f;
float SupremeInfinityPanel::s_infinityEternalInput = 0.1f;
std::string SupremeInfinityPanel::s_selectedStructureId;
std::string SupremeInfinityPanel::s_selectedInfinityId;
std::string SupremeInfinityPanel::s_selectedSupremacyId;
std::string SupremeInfinityPanel::s_selectedInfiniteId;
std::string SupremeInfinityPanel::s_selectedEternalId;
std::vector<nlohmann::json> SupremeInfinityPanel::s_supremeEvents;

void SupremeInfinityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Supreme::SupremeInfinityEngine::Init();
    Supreme::SupremeInfinityLoop::Init();
    Supreme::SupremeInfinityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void SupremeInfinityPanel::Shutdown() {
    if (!s_initialized) return;
    Supreme::SupremeInfinityLoop::Shutdown();
    Supreme::SupremeInfinityEngine::Shutdown();
    s_initialized = false;
}

void SupremeInfinityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Supreme Infinity Panel", &s_visible);
    
    const char* tabs[] = {
        "Supreme Structure", "Ultimate Infinity", "Eternal Supremacy",
        "Infinite Supreme", "Supreme Eternal", "Supreme Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("SupremeTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderSupremeStructureTab(); break;
                    case 1: RenderUltimateInfinityTab(); break;
                    case 2: RenderEternalSupremacyTab(); break;
                    case 3: RenderInfiniteSupremeTab(); break;
                    case 4: RenderSupremeEternalTab(); break;
                    case 5: RenderSupremeMetricsTab(); break;
                    case 6: RenderSupremeVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool SupremeInfinityPanel::IsVisible() {
    return s_visible;
}

void SupremeInfinityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Supreme::SupremeInfinityLoop::IsRunning()) {
        Supreme::SupremeInfinityLoop::Start();
    }
}

void SupremeInfinityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* SupremeInfinityPanel::GetPanelName() {
    return "Supreme Infinity";
}

void SupremeInfinityPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_supremeEvents.push_back(event);
}

void SupremeInfinityPanel::OnInfinityEstablished(const std::string& infinityId) {
    nlohmann::json event;
    event["type"] = "infinity_established";
    event["infinityId"] = infinityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_supremeEvents.push_back(event);
}

void SupremeInfinityPanel::OnSupremacyManifested(const std::string& supremacyId) {
    nlohmann::json event;
    event["type"] = "supremacy_manifested";
    event["supremacyId"] = supremacyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_supremeEvents.push_back(event);
}

void SupremeInfinityPanel::OnInfiniteRealized(const std::string& infiniteId) {
    nlohmann::json event;
    event["type"] = "infinite_realized";
    event["infiniteId"] = infiniteId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_supremeEvents.push_back(event);
}

void SupremeInfinityPanel::OnEternalDiscovered(const std::string& eternalId) {
    nlohmann::json event;
    event["type"] = "eternal_discovered";
    event["eternalId"] = eternalId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_supremeEvents.push_back(event);
}

void SupremeInfinityPanel::RenderSupremeStructureTab() {
    ImGui::Text("Supreme Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Supremacy", &s_supremacyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternality", &s_eternalityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Supreme::SupremeInfinityEngine::CreateSupremeStructure(s_nameBuffer);
        Supreme::SupremeInfinityEngine::ExpandSupremacy(structureId, s_supremacyInput);
        Supreme::SupremeInfinityEngine::AmplifyInfinity(structureId, s_infinityInput);
        Supreme::SupremeInfinityEngine::DeepenEternality(structureId, s_eternalityInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Supreme::SupremeInfinityEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.structureId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.structureId)) {
            s_selectedStructureId = structure.structureId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nSupremacy: %.2f\nInfinity: %.2f\nEternality: %.2f",
                structure.structureId.c_str(), structure.supremacy, structure.infinity, structure.eternality);
        }
        ImGui::PopID();
    }
}

void SupremeInfinityPanel::RenderUltimateInfinityTab() {
    ImGui::Text("Ultimate Infinity Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Ultimacy", &s_ultimacyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Boundlessness", &s_boundlessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Infinity")) {
        std::string infinityId = Supreme::SupremeInfinityEngine::EstablishUltimateInfinity(s_nameBuffer);
        Supreme::SupremeInfinityEngine::IncreaseUltimacy(infinityId, s_ultimacyInput);
        Supreme::SupremeInfinityEngine::ExpandBoundlessness(infinityId, s_boundlessnessInput);
        Supreme::SupremeInfinityEngine::ElevateTranscendence(infinityId, s_transcendenceInput);
        OnInfinityEstablished(infinityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Infinities:");
    auto infinities = Supreme::SupremeInfinityEngine::GetAllInfinities();
    for (const auto& infinity : infinities) {
        ImGui::PushID(infinity.infinityId.c_str());
        bool isSelected = s_selectedInfinityId == infinity.infinityId;
        if (ImGui::Selectable(infinity.name.c_str(), isSelected)) {
            s_selectedInfinityId = infinity.infinityId;
        }
        ImGui::SameLine();
        if (infinity.isUltimate) {
            ImGui::TextColored(ImVec4(1, 0.5, 0, 1), "[ULTIMATE]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[STANDARD]");
        }
        if (s_selectedInfinityId == infinity.infinityId) {
            if (!infinity.isUltimate && ImGui::Button("Declare Ultimate")) {
                Supreme::SupremeInfinityEngine::DeclareUltimate(infinity.infinityId);
            }
        }
        ImGui::PopID();
    }
}

void SupremeInfinityPanel::RenderEternalSupremacyTab() {
    ImGui::Text("Eternal Supremacy Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternality", &s_eternalitySupremacyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinitySupremacyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Supremacy")) {
        std::string supremacyId = Supreme::SupremeInfinityEngine::ManifestEternalSupremacy(s_nameBuffer);
        Supreme::SupremeInfinityEngine::DeepenEternality(supremacyId, s_eternalitySupremacyInput);
        Supreme::SupremeInfinityEngine::AmplifyInfinity(supremacyId, s_infinitySupremacyInput);
        Supreme::SupremeInfinityEngine::ElevateDivinity(supremacyId, s_divinityInput);
        OnSupremacyManifested(supremacyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Supremacies:");
    auto supremacies = Supreme::SupremeInfinityEngine::GetAllSupremacies();
    for (const auto& supremacy : supremacies) {
        ImGui::PushID(supremacy.supremacyId.c_str());
        if (ImGui::Selectable(supremacy.name.c_str(), s_selectedSupremacyId == supremacy.supremacyId)) {
            s_selectedSupremacyId = supremacy.supremacyId;
        }
        if (s_selectedSupremacyId == supremacy.supremacyId) {
            ImGui::Text("Eternality: %.2f | Infinity: %.2f | Divinity: %.2f",
                supremacy.eternality, supremacy.infinity, supremacy.divinity);
            ImGui::Text("Eternal Entities: %zu", supremacy.eternalEntities.size());
        }
        ImGui::PopID();
    }
}

void SupremeInfinityPanel::RenderInfiniteSupremeTab() {
    ImGui::Text("Infinite Supreme Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Infinity", &s_infiniteSupremeInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Supremacy", &s_supremacyInfiniteInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Infinite")) {
        std::string infiniteId = Supreme::SupremeInfinityEngine::RealizeInfiniteSupreme(s_nameBuffer);
        Supreme::SupremeInfinityEngine::AmplifyInfinity(infiniteId, s_infiniteSupremeInput);
        Supreme::SupremeInfinityEngine::ExpandSupremacy(infiniteId, s_supremacyInfiniteInput);
        Supreme::SupremeInfinityEngine::ExtendPerpetuity(infiniteId, s_perpetuityInput);
        OnInfiniteRealized(infiniteId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Infinites:");
    auto infinites = Supreme::SupremeInfinityEngine::GetAllInfinites();
    for (const auto& infinite : infinites) {
        ImGui::PushID(infinite.infiniteId.c_str());
        if (ImGui::Selectable(infinite.name.c_str(), s_selectedInfiniteId == infinite.infiniteId)) {
            s_selectedInfiniteId = infinite.infiniteId;
        }
        ImGui::SameLine();
        if (infinite.isInfinite) {
            ImGui::TextColored(ImVec4(0.5, 0, 1, 1), "[INFINITE]");
        }
        if (s_selectedInfiniteId == infinite.infiniteId) {
            ImGui::Text("Infinity: %.2f | Supremacy: %.2f | Perpetuity: %.2f",
                infinite.infinity, infinite.supremacy, infinite.perpetuity);
            if (!infinite.isInfinite && ImGui::Button("Declare Infinite")) {
                Supreme::SupremeInfinityEngine::DeclareInfinite(infinite.infiniteId);
            }
        }
        ImGui::PopID();
    }
}

void SupremeInfinityPanel::RenderSupremeEternalTab() {
    ImGui::Text("Supreme Eternal Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternality", &s_eternalitySupremeInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Supremacy", &s_supremacyEternalInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityEternalInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Eternal")) {
        std::string eternalId = Supreme::SupremeInfinityEngine::DiscoverSupremeEternal(s_nameBuffer);
        Supreme::SupremeInfinityEngine::DeepenEternality(eternalId, s_eternalitySupremeInput);
        Supreme::SupremeInfinityEngine::ExpandSupremacy(eternalId, s_supremacyEternalInput);
        Supreme::SupremeInfinityEngine::AmplifyInfinity(eternalId, s_infinityEternalInput);
        OnEternalDiscovered(eternalId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Eternals:");
    auto eternals = Supreme::SupremeInfinityEngine::GetAllEternals();
    for (const auto& eternal : eternals) {
        ImGui::PushID(eternal.eternalId.c_str());
        if (ImGui::Selectable(eternal.name.c_str(), s_selectedEternalId == eternal.eternalId)) {
            s_selectedEternalId = eternal.eternalId;
        }
        if (s_selectedEternalId == eternal.eternalId) {
            ImGui::Text("Eternality: %.2f | Supremacy: %.2f | Infinity: %.2f",
                eternal.eternality, eternal.supremacy, eternal.infinity);
            ImGui::Text("Supreme Entities: %zu", eternal.supremeEntities.size());
        }
        ImGui::PopID();
    }
}

void SupremeInfinityPanel::RenderSupremeMetricsTab() {
    ImGui::Text("Supreme Metrics");
    ImGui::Separator();
    
    auto metrics = Supreme::SupremeInfinityEngine::GetSupremeMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Infinity Count: %d", metrics["infinityCount"].get<int>());
    ImGui::Text("Supremacy Count: %d", metrics["supremacyCount"].get<int>());
    ImGui::Text("Infinite Count: %d", metrics["infiniteCount"].get<int>());
    ImGui::Text("Eternal Count: %d", metrics["eternalCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Supremacy: %.4f", metrics["totalSupremacy"].get<float>());
    ImGui::Text("Average Ultimacy: %.4f", metrics["averageUltimacy"].get<float>());
    ImGui::Text("Ultimate Infinities: %d", metrics["ultimateInfinities"].get<int>());
    ImGui::Text("Infinite Supremes: %d", metrics["infiniteSupremes"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Supreme::SupremeInfinityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Supreme Report")) {
        auto report = Supreme::SupremeInfinityEngine::GenerateSupremeReport();
        // Export logic would go here
    }
}

void SupremeInfinityPanel::RenderSupremeVisualizationTab() {
    ImGui::Text("Supreme Visualization");
    ImGui::Separator();
    
    // Draw a representation of supreme infinity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 0, 30, 255));
    
    // Draw supreme structures as radiant stars
    auto structures = Supreme::SupremeInfinityEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 80.0f + structure.supremacy * 50.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 8.0f + structure.infinity * 12.0f;
        
        // Radiant glow effect
        for (int i = 5; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(255, 100, 50, 35 - i * 6), 8);
        }
        // Core star
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 150, 100, 255), 8);
        
        // Label
        draw_list->AddText(ImVec2(x - 35, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw eternal supremacies as divine rings
    auto supremacies = Supreme::SupremeInfinityEngine::GetAllSupremacies();
    int supremacyIdx = 0;
    for (const auto& supremacy : supremacies) {
        float baseRadius = 40.0f + supremacyIdx * 25.0f;
        float pulse = (std::sin(ImGui::GetTime() * 1.5f + supremacyIdx * 0.5f) + 1.0f) * 0.5f;
        float radius = baseRadius + pulse * 15.0f;
        float thickness = 2.0f + supremacy.divinity * 4.0f;
        ImU32 color = IM_COL32(255, 200, 100, 150 + supremacy.eternality * 100);
        
        draw_list->AddCircle(ImVec2(centerX, centerY), radius, color, 64, thickness);
        supremacyIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Supreme Event Log:");
    ImGui::BeginChild("SupremeEvents", ImVec2(0, 150), true);
    for (auto it = s_supremeEvents.rbegin(); it != s_supremeEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
