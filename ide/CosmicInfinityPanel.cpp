#include "ide/CosmicInfinityPanel.hpp"
#include "infinity/CosmicInfinityEngine.hpp"
#include "infinity/CosmicInfinityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool CosmicInfinityPanel::s_visible = false;
bool CosmicInfinityPanel::s_initialized = false;
int CosmicInfinityPanel::s_selectedTab = 0;
char CosmicInfinityPanel::s_nameBuffer[256] = {};
char CosmicInfinityPanel::s_entityIdBuffer[256] = {};
char CosmicInfinityPanel::s_attributeKeyBuffer[256] = {};
char CosmicInfinityPanel::s_attributeValueBuffer[512] = {};
float CosmicInfinityPanel::s_boundlessnessInput = 0.1f;
float CosmicInfinityPanel::s_endlessnessInput = 0.1f;
float CosmicInfinityPanel::s_limitlessnessInput = 0.1f;
float CosmicInfinityPanel::s_expansivenessInput = 0.1f;
float CosmicInfinityPanel::s_vastnessInput = 0.1f;
float CosmicInfinityPanel::s_immensityInput = 0.1f;
float CosmicInfinityPanel::s_perpetuityInput = 0.1f;
float CosmicInfinityPanel::s_timelessnessInput = 0.1f;
float CosmicInfinityPanel::s_permanenceInput = 1.0f;
float CosmicInfinityPanel::s_omnipresenceInput = 0.1f;
float CosmicInfinityPanel::s_ubiquityInput = 0.1f;
float CosmicInfinityPanel::s_infinityInput = 0.1f;
float CosmicInfinityPanel::s_horizonInput = 0.1f;
float CosmicInfinityPanel::s_frontierInput = 0.1f;
float CosmicInfinityPanel::s_edgeInput = 0.1f;
std::string CosmicInfinityPanel::s_selectedStructureId;
std::string CosmicInfinityPanel::s_selectedExistenceId;
std::string CosmicInfinityPanel::s_selectedContinuumId;
std::string CosmicInfinityPanel::s_selectedInfinityId;
std::string CosmicInfinityPanel::s_selectedHorizonId;
std::vector<nlohmann::json> CosmicInfinityPanel::s_infinityEvents;

void CosmicInfinityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Infinity::CosmicInfinityEngine::Init();
    Infinity::CosmicInfinityLoop::Init();
    Infinity::CosmicInfinityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void CosmicInfinityPanel::Shutdown() {
    if (!s_initialized) return;
    Infinity::CosmicInfinityLoop::Shutdown();
    Infinity::CosmicInfinityEngine::Shutdown();
    s_initialized = false;
}

void CosmicInfinityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Cosmic Infinity Panel", &s_visible);
    
    const char* tabs[] = {
        "Infinite Structure", "Boundless Existence", "Eternal Continuum",
        "Omniversal Infinity", "Infinite Horizon", "Infinity Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("InfinityTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderInfiniteStructureTab(); break;
                    case 1: RenderBoundlessExistenceTab(); break;
                    case 2: RenderEternalContinuumTab(); break;
                    case 3: RenderOmniversalInfinityTab(); break;
                    case 4: RenderInfiniteHorizonTab(); break;
                    case 5: RenderInfinityMetricsTab(); break;
                    case 6: RenderInfinityVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool CosmicInfinityPanel::IsVisible() {
    return s_visible;
}

void CosmicInfinityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Infinity::CosmicInfinityLoop::IsRunning()) {
        Infinity::CosmicInfinityLoop::Start();
    }
}

void CosmicInfinityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* CosmicInfinityPanel::GetPanelName() {
    return "Cosmic Infinity";
}

void CosmicInfinityPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_infinityEvents.push_back(event);
}

void CosmicInfinityPanel::OnExistenceManifested(const std::string& existenceId) {
    nlohmann::json event;
    event["type"] = "existence_manifested";
    event["existenceId"] = existenceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_infinityEvents.push_back(event);
}

void CosmicInfinityPanel::OnContinuumEstablished(const std::string& continuumId) {
    nlohmann::json event;
    event["type"] = "continuum_established";
    event["continuumId"] = continuumId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_infinityEvents.push_back(event);
}

void CosmicInfinityPanel::OnInfinityRealized(const std::string& infinityId) {
    nlohmann::json event;
    event["type"] = "infinity_realized";
    event["infinityId"] = infinityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_infinityEvents.push_back(event);
}

void CosmicInfinityPanel::OnHorizonDiscovered(const std::string& horizonId) {
    nlohmann::json event;
    event["type"] = "horizon_discovered";
    event["horizonId"] = horizonId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_infinityEvents.push_back(event);
}

void CosmicInfinityPanel::RenderInfiniteStructureTab() {
    ImGui::Text("Infinite Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Boundlessness", &s_boundlessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Endlessness", &s_endlessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Limitlessness", &s_limitlessnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Infinity::CosmicInfinityEngine::CreateInfiniteStructure(s_nameBuffer);
        Infinity::CosmicInfinityEngine::ExpandBoundlessness(structureId, s_boundlessnessInput);
        Infinity::CosmicInfinityEngine::ExtendEndlessness(structureId, s_endlessnessInput);
        Infinity::CosmicInfinityEngine::IncreaseLimitlessness(structureId, s_limitlessnessInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Infinity::CosmicInfinityEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.structureId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.structureId)) {
            s_selectedStructureId = structure.structureId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nBoundlessness: %.2f\nEndlessness: %.2f\nLimitlessness: %.2f",
                structure.structureId.c_str(), structure.boundlessness, structure.endlessness, structure.limitlessness);
        }
        ImGui::PopID();
    }
}

void CosmicInfinityPanel::RenderBoundlessExistenceTab() {
    ImGui::Text("Boundless Existence Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Expansiveness", &s_expansivenessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Vastness", &s_vastnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Immensity", &s_immensityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Existence")) {
        std::string existenceId = Infinity::CosmicInfinityEngine::ManifestBoundlessExistence(s_nameBuffer);
        Infinity::CosmicInfinityEngine::ExpandExpansiveness(existenceId, s_expansivenessInput);
        Infinity::CosmicInfinityEngine::IncreaseVastness(existenceId, s_vastnessInput);
        Infinity::CosmicInfinityEngine::AmplifyImmensity(existenceId, s_immensityInput);
        OnExistenceManifested(existenceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Existences:");
    auto existences = Infinity::CosmicInfinityEngine::GetAllExistences();
    for (const auto& existence : existences) {
        ImGui::PushID(existence.existenceId.c_str());
        bool isSelected = s_selectedExistenceId == existence.existenceId;
        if (ImGui::Selectable(existence.name.c_str(), isSelected)) {
            s_selectedExistenceId = existence.existenceId;
        }
        ImGui::SameLine();
        if (existence.isUnbounded) {
            ImGui::TextColored(ImVec4(0, 1, 1, 1), "[UNBOUNDED]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[BOUNDED]");
        }
        if (s_selectedExistenceId == existence.existenceId) {
            if (!existence.isUnbounded && ImGui::Button("Declare Unbounded")) {
                Infinity::CosmicInfinityEngine::DeclareUnbounded(existence.existenceId);
            }
        }
        ImGui::PopID();
    }
}

void CosmicInfinityPanel::RenderEternalContinuumTab() {
    ImGui::Text("Eternal Continuum Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Timelessness", &s_timelessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Permanence", &s_permanenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Continuum")) {
        std::string continuumId = Infinity::CosmicInfinityEngine::EstablishContinuum(s_nameBuffer);
        Infinity::CosmicInfinityEngine::ExtendPerpetuity(continuumId, s_perpetuityInput);
        Infinity::CosmicInfinityEngine::DeepenTimelessness(continuumId, s_timelessnessInput);
        Infinity::CosmicInfinityEngine::StrengthenPermanence(continuumId, s_permanenceInput);
        OnContinuumEstablished(continuumId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Continuums:");
    auto continuums = Infinity::CosmicInfinityEngine::GetAllContinuums();
    for (const auto& continuum : continuums) {
        ImGui::PushID(continuum.continuumId.c_str());
        if (ImGui::Selectable(continuum.name.c_str(), s_selectedContinuumId == continuum.continuumId)) {
            s_selectedContinuumId = continuum.continuumId;
        }
        if (s_selectedContinuumId == continuum.continuumId) {
            ImGui::Text("Perpetuity: %.2f | Timelessness: %.2f | Permanence: %.2f",
                continuum.perpetuity, continuum.timelessness, continuum.permanence);
            ImGui::Text("Temporal Entities: %zu", continuum.temporalEntities.size());
        }
        ImGui::PopID();
    }
}

void CosmicInfinityPanel::RenderOmniversalInfinityTab() {
    ImGui::Text("Omniversal Infinity Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Omnipresence", &s_omnipresenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Ubiquity", &s_ubiquityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Infinity")) {
        std::string infinityId = Infinity::CosmicInfinityEngine::RealizeOmniversalInfinity(s_nameBuffer);
        Infinity::CosmicInfinityEngine::ExpandOmnipresence(infinityId, s_omnipresenceInput);
        Infinity::CosmicInfinityEngine::IncreaseUbiquity(infinityId, s_ubiquityInput);
        Infinity::CosmicInfinityEngine::AmplifyInfinity(infinityId, s_infinityInput);
        OnInfinityRealized(infinityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Infinities:");
    auto infinities = Infinity::CosmicInfinityEngine::GetAllOmniversalInfinities();
    for (const auto& infinity : infinities) {
        ImGui::PushID(infinity.infinityId.c_str());
        if (ImGui::Selectable(infinity.name.c_str(), s_selectedInfinityId == infinity.infinityId)) {
            s_selectedInfinityId = infinity.infinityId;
        }
        ImGui::SameLine();
        if (infinity.isAbsolute) {
            ImGui::TextColored(ImVec4(1, 0, 1, 1), "[ABSOLUTE]");
        }
        if (s_selectedInfinityId == infinity.infinityId) {
            ImGui::Text("Omnipresence: %.2f | Ubiquity: %.2f | Infinity: %.2f",
                infinity.omnipresence, infinity.ubiquity, infinity.infinity);
            if (!infinity.isAbsolute && ImGui::Button("Declare Absolute")) {
                Infinity::CosmicInfinityEngine::DeclareAbsolute(infinity.infinityId);
            }
        }
        ImGui::PopID();
    }
}

void CosmicInfinityPanel::RenderInfiniteHorizonTab() {
    ImGui::Text("Infinite Horizon Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Horizon", &s_horizonInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Frontier", &s_frontierInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Edge", &s_edgeInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Horizon")) {
        std::string horizonId = Infinity::CosmicInfinityEngine::DiscoverHorizon(s_nameBuffer);
        Infinity::CosmicInfinityEngine::ExtendHorizon(horizonId, s_horizonInput);
        Infinity::CosmicInfinityEngine::ExpandFrontier(horizonId, s_frontierInput);
        Infinity::CosmicInfinityEngine::PushEdge(horizonId, s_edgeInput);
        OnHorizonDiscovered(horizonId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Horizons:");
    auto horizons = Infinity::CosmicInfinityEngine::GetAllHorizons();
    for (const auto& horizon : horizons) {
        ImGui::PushID(horizon.horizonId.c_str());
        if (ImGui::Selectable(horizon.name.c_str(), s_selectedHorizonId == horizon.horizonId)) {
            s_selectedHorizonId = horizon.horizonId;
        }
        if (s_selectedHorizonId == horizon.horizonId) {
            ImGui::Text("Horizon: %.2f | Frontier: %.2f | Edge: %.2f",
                horizon.horizon, horizon.frontier, horizon.edge);
            ImGui::Text("Beyond Entities: %zu", horizon.beyondEntities.size());
        }
        ImGui::PopID();
    }
}

void CosmicInfinityPanel::RenderInfinityMetricsTab() {
    ImGui::Text("Infinity Metrics");
    ImGui::Separator();
    
    auto metrics = Infinity::CosmicInfinityEngine::GetInfinityMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Existence Count: %d", metrics["existenceCount"].get<int>());
    ImGui::Text("Continuum Count: %d", metrics["continuumCount"].get<int>());
    ImGui::Text("Infinity Count: %d", metrics["infinityCount"].get<int>());
    ImGui::Text("Horizon Count: %d", metrics["horizonCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Boundlessness: %.4f", metrics["totalBoundlessness"].get<float>());
    ImGui::Text("Average Expansiveness: %.4f", metrics["averageExpansiveness"].get<float>());
    ImGui::Text("Unbounded Existences: %d", metrics["unboundedExistences"].get<int>());
    ImGui::Text("Absolute Infinities: %d", metrics["absoluteInfinities"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Infinity::CosmicInfinityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Infinity Report")) {
        auto report = Infinity::CosmicInfinityEngine::GenerateInfinityReport();
        // Export logic would go here
    }
}

void CosmicInfinityPanel::RenderInfinityVisualizationTab() {
    ImGui::Text("Infinity Visualization");
    ImGui::Separator();
    
    // Draw a representation of cosmic infinity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(5, 5, 20, 255));
    
    // Draw infinite structures as expanding circles
    auto structures = Infinity::CosmicInfinityEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 50.0f + structure.boundlessness * 80.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 8.0f + structure.endlessness * 15.0f;
        
        // Infinity glow effect
        for (int i = 4; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(0, 255, 255, 40 - i * 8), 16);
        }
        // Core
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(0, 255, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw eternal continuums as flowing lines
    auto continuums = Infinity::CosmicInfinityEngine::GetAllContinuums();
    int continuumIdx = 0;
    for (const auto& continuum : continuums) {
        float y = canvas_pos.y + 40 + continuumIdx * 30;
        float thickness = 1.0f + continuum.perpetuity * 4.0f;
        ImU32 color = IM_COL32(255, 100, 255, 150 + continuum.timelessness * 100);
        
        // Draw wavy line to represent eternal flow
        for (int x = 20; x < canvas_size.x - 20; x += 5) {
            float waveY = y + std::sin(x * 0.05f + continuumIdx) * 5.0f;
            draw_list->AddCircleFilled(ImVec2(canvas_pos.x + x, waveY), thickness, color);
        }
        
        draw_list->AddText(ImVec2(canvas_pos.x + 25, y - 10), IM_COL32(255, 255, 255, 200), continuum.name.c_str());
        continuumIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Infinity Event Log:");
    ImGui::BeginChild("InfinityEvents", ImVec2(0, 150), true);
    for (auto it = s_infinityEvents.rbegin(); it != s_infinityEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
