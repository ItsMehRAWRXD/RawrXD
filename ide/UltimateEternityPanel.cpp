#include "ide/UltimateEternityPanel.hpp"
#include "eternity/UltimateEternityEngine.hpp"
#include "eternity/UltimateEternityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool UltimateEternityPanel::s_visible = false;
bool UltimateEternityPanel::s_initialized = false;
int UltimateEternityPanel::s_selectedTab = 0;
char UltimateEternityPanel::s_nameBuffer[256] = {};
char UltimateEternityPanel::s_entityIdBuffer[256] = {};
char UltimateEternityPanel::s_attributeKeyBuffer[256] = {};
char UltimateEternityPanel::s_attributeValueBuffer[512] = {};
float UltimateEternityPanel::s_forevernessInput = 0.1f;
float UltimateEternityPanel::s_perpetuityInput = 0.1f;
float UltimateEternityPanel::s_endlessnessInput = 0.1f;
float UltimateEternityPanel::s_timelessnessInput = 0.1f;
float UltimateEternityPanel::s_infinityInput = 0.1f;
float UltimateEternityPanel::s_permanenceInput = 0.1f;
float UltimateEternityPanel::s_durationInput = 0.1f;
float UltimateEternityPanel::s_continuityInput = 0.1f;
float UltimateEternityPanel::s_persistenceInput = 0.1f;
float UltimateEternityPanel::s_perpetuationInput = 0.1f;
float UltimateEternityPanel::s_sustainabilityInput = 0.1f;
float UltimateEternityPanel::s_immortalityInput = 0.1f;
float UltimateEternityPanel::s_eternityInput = 0.1f;
float UltimateEternityPanel::s_vastnessInput = 0.1f;
float UltimateEternityPanel::s_infinityHorizonInput = 0.1f;
std::string UltimateEternityPanel::s_selectedStructureId;
std::string UltimateEternityPanel::s_selectedContinuumId;
std::string UltimateEternityPanel::s_selectedTimeId;
std::string UltimateEternityPanel::s_selectedExistenceId;
std::string UltimateEternityPanel::s_selectedHorizonId;
std::vector<nlohmann::json> UltimateEternityPanel::s_eternityEvents;

void UltimateEternityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Eternity::UltimateEternityEngine::Init();
    Eternity::UltimateEternityLoop::Init();
    Eternity::UltimateEternityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void UltimateEternityPanel::Shutdown() {
    if (!s_initialized) return;
    Eternity::UltimateEternityLoop::Shutdown();
    Eternity::UltimateEternityEngine::Shutdown();
    s_initialized = false;
}

void UltimateEternityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Ultimate Eternity Panel", &s_visible);
    
    const char* tabs[] = {
        "Ultimate Structure", "Forever Continuum", "Endless Time",
        "Perpetual Existence", "Eternal Horizon", "Eternity Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("EternityTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderUltimateStructureTab(); break;
                    case 1: RenderForeverContinuumTab(); break;
                    case 2: RenderEndlessTimeTab(); break;
                    case 3: RenderPerpetualExistenceTab(); break;
                    case 4: RenderEternalHorizonTab(); break;
                    case 5: RenderEternityMetricsTab(); break;
                    case 6: RenderEternityVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool UltimateEternityPanel::IsVisible() {
    return s_visible;
}

void UltimateEternityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Eternity::UltimateEternityLoop::IsRunning()) {
        Eternity::UltimateEternityLoop::Start();
    }
}

void UltimateEternityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* UltimateEternityPanel::GetPanelName() {
    return "Ultimate Eternity";
}

void UltimateEternityPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_eternityEvents.push_back(event);
}

void UltimateEternityPanel::OnContinuumEstablished(const std::string& continuumId) {
    nlohmann::json event;
    event["type"] = "continuum_established";
    event["continuumId"] = continuumId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_eternityEvents.push_back(event);
}

void UltimateEternityPanel::OnTimeBegun(const std::string& timeId) {
    nlohmann::json event;
    event["type"] = "time_begun";
    event["timeId"] = timeId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_eternityEvents.push_back(event);
}

void UltimateEternityPanel::OnExistenceManifested(const std::string& existenceId) {
    nlohmann::json event;
    event["type"] = "existence_manifested";
    event["existenceId"] = existenceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_eternityEvents.push_back(event);
}

void UltimateEternityPanel::OnHorizonDiscovered(const std::string& horizonId) {
    nlohmann::json event;
    event["type"] = "horizon_discovered";
    event["horizonId"] = horizonId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_eternityEvents.push_back(event);
}

void UltimateEternityPanel::RenderUltimateStructureTab() {
    ImGui::Text("Ultimate Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Foreverness", &s_forevernessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Endlessness", &s_endlessnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Eternity::UltimateEternityEngine::CreateUltimateStructure(s_nameBuffer);
        Eternity::UltimateEternityEngine::ExpandForeverness(structureId, s_forevernessInput);
        Eternity::UltimateEternityEngine::ExtendPerpetuity(structureId, s_perpetuityInput);
        Eternity::UltimateEternityEngine::IncreaseEndlessness(structureId, s_endlessnessInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Eternity::UltimateEternityEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.structureId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.structureId)) {
            s_selectedStructureId = structure.structureId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nForeverness: %.2f\nPerpetuity: %.2f\nEndlessness: %.2f",
                structure.structureId.c_str(), structure.foreverness, structure.perpetuity, structure.endlessness);
        }
        ImGui::PopID();
    }
}

void UltimateEternityPanel::RenderForeverContinuumTab() {
    ImGui::Text("Forever Continuum Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Timelessness", &s_timelessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Permanence", &s_permanenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Continuum")) {
        std::string continuumId = Eternity::UltimateEternityEngine::EstablishForeverContinuum(s_nameBuffer);
        Eternity::UltimateEternityEngine::DeepenTimelessness(continuumId, s_timelessnessInput);
        Eternity::UltimateEternityEngine::ExpandInfinity(continuumId, s_infinityInput);
        Eternity::UltimateEternityEngine::StrengthenPermanence(continuumId, s_permanenceInput);
        OnContinuumEstablished(continuumId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Continuums:");
    auto continuums = Eternity::UltimateEternityEngine::GetAllContinuums();
    for (const auto& continuum : continuums) {
        ImGui::PushID(continuum.continuumId.c_str());
        bool isSelected = s_selectedContinuumId == continuum.continuumId;
        if (ImGui::Selectable(continuum.name.c_str(), isSelected)) {
            s_selectedContinuumId = continuum.continuumId;
        }
        ImGui::SameLine();
        if (continuum.isForever) {
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "[FOREVER]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[TEMPORARY]");
        }
        if (s_selectedContinuumId == continuum.continuumId) {
            if (!continuum.isForever && ImGui::Button("Declare Forever")) {
                Eternity::UltimateEternityEngine::DeclareForever(continuum.continuumId);
            }
        }
        ImGui::PopID();
    }
}

void UltimateEternityPanel::RenderEndlessTimeTab() {
    ImGui::Text("Endless Time Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Duration", &s_durationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Continuity", &s_continuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Persistence", &s_persistenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Begin Time")) {
        std::string timeId = Eternity::UltimateEternityEngine::BeginEndlessTime(s_nameBuffer);
        Eternity::UltimateEternityEngine::ExtendDuration(timeId, s_durationInput);
        Eternity::UltimateEternityEngine::EnsureContinuity(timeId, s_continuityInput);
        Eternity::UltimateEternityEngine::StrengthenPersistence(timeId, s_persistenceInput);
        OnTimeBegun(timeId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Begun Times:");
    auto times = Eternity::UltimateEternityEngine::GetAllTimes();
    for (const auto& time : times) {
        ImGui::PushID(time.timeId.c_str());
        if (ImGui::Selectable(time.name.c_str(), s_selectedTimeId == time.timeId)) {
            s_selectedTimeId = time.timeId;
        }
        if (s_selectedTimeId == time.timeId) {
            ImGui::Text("Duration: %.2f | Continuity: %.2f | Persistence: %.2f",
                time.duration, time.continuity, time.persistence);
            ImGui::Text("Temporal Entities: %zu", time.temporalEntities.size());
        }
        ImGui::PopID();
    }
}

void UltimateEternityPanel::RenderPerpetualExistenceTab() {
    ImGui::Text("Perpetual Existence Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Perpetuation", &s_perpetuationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sustainability", &s_sustainabilityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Immortality", &s_immortalityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Existence")) {
        std::string existenceId = Eternity::UltimateEternityEngine::ManifestPerpetualExistence(s_nameBuffer);
        Eternity::UltimateEternityEngine::IncreasePerpetuation(existenceId, s_perpetuationInput);
        Eternity::UltimateEternityEngine::EnsureSustainability(existenceId, s_sustainabilityInput);
        Eternity::UltimateEternityEngine::AchieveImmortality(existenceId, s_immortalityInput);
        OnExistenceManifested(existenceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Existences:");
    auto existences = Eternity::UltimateEternityEngine::GetAllExistences();
    for (const auto& existence : existences) {
        ImGui::PushID(existence.existenceId.c_str());
        if (ImGui::Selectable(existence.name.c_str(), s_selectedExistenceId == existence.existenceId)) {
            s_selectedExistenceId = existence.existenceId;
        }
        ImGui::SameLine();
        if (existence.isPerpetual) {
            ImGui::TextColored(ImVec4(1, 0.5, 0, 1), "[PERPETUAL]");
        }
        if (s_selectedExistenceId == existence.existenceId) {
            ImGui::Text("Perpetuation: %.2f | Sustainability: %.2f | Immortality: %.2f",
                existence.perpetuation, existence.sustainability, existence.immortality);
            if (!existence.isPerpetual && ImGui::Button("Declare Perpetual")) {
                Eternity::UltimateEternityEngine::DeclarePerpetual(existence.existenceId);
            }
        }
        ImGui::PopID();
    }
}

void UltimateEternityPanel::RenderEternalHorizonTab() {
    ImGui::Text("Eternal Horizon Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternity", &s_eternityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Vastness", &s_vastnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityHorizonInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Horizon")) {
        std::string horizonId = Eternity::UltimateEternityEngine::DiscoverEternalHorizon(s_nameBuffer);
        Eternity::UltimateEternityEngine::ExtendEternity(horizonId, s_eternityInput);
        Eternity::UltimateEternityEngine::ExpandVastness(horizonId, s_vastnessInput);
        Eternity::UltimateEternityEngine::AmplifyInfinity(horizonId, s_infinityHorizonInput);
        OnHorizonDiscovered(horizonId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Horizons:");
    auto horizons = Eternity::UltimateEternityEngine::GetAllHorizons();
    for (const auto& horizon : horizons) {
        ImGui::PushID(horizon.horizonId.c_str());
        if (ImGui::Selectable(horizon.name.c_str(), s_selectedHorizonId == horizon.horizonId)) {
            s_selectedHorizonId = horizon.horizonId;
        }
        if (s_selectedHorizonId == horizon.horizonId) {
            ImGui::Text("Eternity: %.2f | Vastness: %.2f | Infinity: %.2f",
                horizon.eternity, horizon.vastness, horizon.infinity);
            ImGui::Text("Beyond Entities: %zu", horizon.beyondEntities.size());
        }
        ImGui::PopID();
    }
}

void UltimateEternityPanel::RenderEternityMetricsTab() {
    ImGui::Text("Eternity Metrics");
    ImGui::Separator();
    
    auto metrics = Eternity::UltimateEternityEngine::GetEternityMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Continuum Count: %d", metrics["continuumCount"].get<int>());
    ImGui::Text("Time Count: %d", metrics["timeCount"].get<int>());
    ImGui::Text("Existence Count: %d", metrics["existenceCount"].get<int>());
    ImGui::Text("Horizon Count: %d", metrics["horizonCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Foreverness: %.4f", metrics["totalForeverness"].get<float>());
    ImGui::Text("Average Timelessness: %.4f", metrics["averageTimelessness"].get<float>());
    ImGui::Text("Forever Continuums: %d", metrics["foreverContinuums"].get<int>());
    ImGui::Text("Perpetual Existences: %d", metrics["perpetualExistences"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Eternity::UltimateEternityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Eternity Report")) {
        auto report = Eternity::UltimateEternityEngine::GenerateEternityReport();
        // Export logic would go here
    }
}

void UltimateEternityPanel::RenderEternityVisualizationTab() {
    ImGui::Text("Eternity Visualization");
    ImGui::Separator();
    
    // Draw a representation of ultimate eternity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(0, 10, 20, 255));
    
    // Draw ultimate structures as eternal stars
    auto structures = Eternity::UltimateEternityEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.foreverness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.endlessness * 12.0f;
        
        // Star glow effect
        for (int i = 5; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 4, IM_COL32(255, 255, 200, 30 - i * 5), 16);
        }
        // Core star
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 255, 220, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 30, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw endless times as spiraling trails
    auto times = Eternity::UltimateEternityEngine::GetAllTimes();
    int timeIdx = 0;
    for (const auto& time : times) {
        float thickness = 1.0f + time.duration * 3.0f;
        ImU32 color = IM_COL32(200, 150, 255, 100 + time.continuity * 100);
        
        // Draw spiral
        for (float t = 0; t < 4 * 3.14159f; t += 0.1f) {
            float r = 20.0f + t * 8.0f;
            float x = centerX + std::cos(t + timeIdx) * r;
            float y = centerY + std::sin(t + timeIdx) * r;
            draw_list->AddCircleFilled(ImVec2(x, y), thickness, color);
        }
        
        timeIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Eternity Event Log:");
    ImGui::BeginChild("EternityEvents", ImVec2(0, 150), true);
    for (auto it = s_eternityEvents.rbegin(); it != s_eternityEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
