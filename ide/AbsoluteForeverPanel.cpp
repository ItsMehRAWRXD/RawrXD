#include "ide/AbsoluteForeverPanel.hpp"
#include "absolute/AbsoluteForeverEngine.hpp"
#include "absolute/AbsoluteForeverLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool AbsoluteForeverPanel::s_visible = false;
bool AbsoluteForeverPanel::s_initialized = false;
int AbsoluteForeverPanel::s_selectedTab = 0;
char AbsoluteForeverPanel::s_nameBuffer[256] = {};
char AbsoluteForeverPanel::s_entityIdBuffer[256] = {};
char AbsoluteForeverPanel::s_attributeKeyBuffer[256] = {};
char AbsoluteForeverPanel::s_attributeValueBuffer[512] = {};
float AbsoluteForeverPanel::s_absolutenessInput = 0.1f;
float AbsoluteForeverPanel::s_perpetuityInput = 0.1f;
float AbsoluteForeverPanel::s_eternalityInput = 0.1f;
float AbsoluteForeverPanel::s_perpetuationInput = 0.1f;
float AbsoluteForeverPanel::s_sustainabilityInput = 0.1f;
float AbsoluteForeverPanel::s_continuityInput = 0.1f;
float AbsoluteForeverPanel::s_eternalityAbsoluteInput = 0.1f;
float AbsoluteForeverPanel::s_infinityInput = 0.1f;
float AbsoluteForeverPanel::s_transcendenceInput = 0.1f;
float AbsoluteForeverPanel::s_forevernessInput = 0.1f;
float AbsoluteForeverPanel::s_permanenceInput = 0.1f;
float AbsoluteForeverPanel::s_immortalityInput = 0.1f;
float AbsoluteForeverPanel::s_infinityAbsoluteInput = 0.1f;
float AbsoluteForeverPanel::s_boundlessnessInput = 0.1f;
float AbsoluteForeverPanel::s_limitlessnessInput = 0.1f;
std::string AbsoluteForeverPanel::s_selectedStructureId;
std::string AbsoluteForeverPanel::s_selectedPerpetuityId;
std::string AbsoluteForeverPanel::s_selectedAbsoluteId;
std::string AbsoluteForeverPanel::s_selectedExistenceId;
std::string AbsoluteForeverPanel::s_selectedInfiniteId;
std::vector<nlohmann::json> AbsoluteForeverPanel::s_absoluteEvents;

void AbsoluteForeverPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Absolute::AbsoluteForeverEngine::Init();
    Absolute::AbsoluteForeverLoop::Init();
    Absolute::AbsoluteForeverLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void AbsoluteForeverPanel::Shutdown() {
    if (!s_initialized) return;
    Absolute::AbsoluteForeverLoop::Shutdown();
    Absolute::AbsoluteForeverEngine::Shutdown();
    s_initialized = false;
}

void AbsoluteForeverPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Absolute Forever Panel", &s_visible);
    
    const char* tabs[] = {
        "Absolute Structure", "Ultimate Perpetuity", "Eternal Absolute",
        "Forever Existence", "Infinite Absolute", "Absolute Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("AbsoluteTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderAbsoluteStructureTab(); break;
                    case 1: RenderUltimatePerpetuityTab(); break;
                    case 2: RenderEternalAbsoluteTab(); break;
                    case 3: RenderForeverExistenceTab(); break;
                    case 4: RenderInfiniteAbsoluteTab(); break;
                    case 5: RenderAbsoluteMetricsTab(); break;
                    case 6: RenderAbsoluteVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool AbsoluteForeverPanel::IsVisible() {
    return s_visible;
}

void AbsoluteForeverPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Absolute::AbsoluteForeverLoop::IsRunning()) {
        Absolute::AbsoluteForeverLoop::Start();
    }
}

void AbsoluteForeverPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* AbsoluteForeverPanel::GetPanelName() {
    return "Absolute Forever";
}

void AbsoluteForeverPanel::OnStructureCreated(const std::string& structureId) {
    nlohmann::json event;
    event["type"] = "structure_created";
    event["structureId"] = structureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_absoluteEvents.push_back(event);
}

void AbsoluteForeverPanel::OnPerpetuityEstablished(const std::string& perpetuityId) {
    nlohmann::json event;
    event["type"] = "perpetuity_established";
    event["perpetuityId"] = perpetuityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_absoluteEvents.push_back(event);
}

void AbsoluteForeverPanel::OnAbsoluteManifested(const std::string& absoluteId) {
    nlohmann::json event;
    event["type"] = "absolute_manifested";
    event["absoluteId"] = absoluteId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_absoluteEvents.push_back(event);
}

void AbsoluteForeverPanel::OnExistenceRealized(const std::string& existenceId) {
    nlohmann::json event;
    event["type"] = "existence_realized";
    event["existenceId"] = existenceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_absoluteEvents.push_back(event);
}

void AbsoluteForeverPanel::OnInfiniteDiscovered(const std::string& infiniteId) {
    nlohmann::json event;
    event["type"] = "infinite_discovered";
    event["infiniteId"] = infiniteId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_absoluteEvents.push_back(event);
}

void AbsoluteForeverPanel::RenderAbsoluteStructureTab() {
    ImGui::Text("Absolute Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Absoluteness", &s_absolutenessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Perpetuity", &s_perpetuityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternality", &s_eternalityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string structureId = Absolute::AbsoluteForeverEngine::CreateAbsoluteStructure(s_nameBuffer);
        Absolute::AbsoluteForeverEngine::ExpandAbsoluteness(structureId, s_absolutenessInput);
        Absolute::AbsoluteForeverEngine::ExtendPerpetuity(structureId, s_perpetuityInput);
        Absolute::AbsoluteForeverEngine::IncreaseEternality(structureId, s_eternalityInput);
        OnStructureCreated(structureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = Absolute::AbsoluteForeverEngine::GetAllStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.structureId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedStructureId == structure.structureId)) {
            s_selectedStructureId = structure.structureId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nAbsoluteness: %.2f\nPerpetuity: %.2f\nEternality: %.2f",
                structure.structureId.c_str(), structure.absoluteness, structure.perpetuity, structure.eternality);
        }
        ImGui::PopID();
    }
}

void AbsoluteForeverPanel::RenderUltimatePerpetuityTab() {
    ImGui::Text("Ultimate Perpetuity Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Perpetuation", &s_perpetuationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sustainability", &s_sustainabilityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Continuity", &s_continuityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Perpetuity")) {
        std::string perpetuityId = Absolute::AbsoluteForeverEngine::EstablishUltimatePerpetuity(s_nameBuffer);
        Absolute::AbsoluteForeverEngine::IncreasePerpetuation(perpetuityId, s_perpetuationInput);
        Absolute::AbsoluteForeverEngine::EnsureSustainability(perpetuityId, s_sustainabilityInput);
        Absolute::AbsoluteForeverEngine::MaintainContinuity(perpetuityId, s_continuityInput);
        OnPerpetuityEstablished(perpetuityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Perpetuities:");
    auto perpetuities = Absolute::AbsoluteForeverEngine::GetAllPerpetuities();
    for (const auto& perpetuity : perpetuities) {
        ImGui::PushID(perpetuity.perpetuityId.c_str());
        bool isSelected = s_selectedPerpetuityId == perpetuity.perpetuityId;
        if (ImGui::Selectable(perpetuity.name.c_str(), isSelected)) {
            s_selectedPerpetuityId = perpetuity.perpetuityId;
        }
        ImGui::SameLine();
        if (perpetuity.isUltimate) {
            ImGui::TextColored(ImVec4(1, 0, 1, 1), "[ULTIMATE]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[STANDARD]");
        }
        if (s_selectedPerpetuityId == perpetuity.perpetuityId) {
            if (!perpetuity.isUltimate && ImGui::Button("Declare Ultimate")) {
                Absolute::AbsoluteForeverEngine::DeclareUltimate(perpetuity.perpetuityId);
            }
        }
        ImGui::PopID();
    }
}

void AbsoluteForeverPanel::RenderEternalAbsoluteTab() {
    ImGui::Text("Eternal Absolute Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Eternality", &s_eternalityAbsoluteInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Absolute")) {
        std::string absoluteId = Absolute::AbsoluteForeverEngine::ManifestEternalAbsolute(s_nameBuffer);
        Absolute::AbsoluteForeverEngine::DeepenEternality(absoluteId, s_eternalityAbsoluteInput);
        Absolute::AbsoluteForeverEngine::ExpandInfinity(absoluteId, s_infinityInput);
        Absolute::AbsoluteForeverEngine::ElevateTranscendence(absoluteId, s_transcendenceInput);
        OnAbsoluteManifested(absoluteId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Absolutes:");
    auto absolutes = Absolute::AbsoluteForeverEngine::GetAllAbsolutes();
    for (const auto& absolute : absolutes) {
        ImGui::PushID(absolute.absoluteId.c_str());
        if (ImGui::Selectable(absolute.name.c_str(), s_selectedAbsoluteId == absolute.absoluteId)) {
            s_selectedAbsoluteId = absolute.absoluteId;
        }
        if (s_selectedAbsoluteId == absolute.absoluteId) {
            ImGui::Text("Eternality: %.2f | Infinity: %.2f | Transcendence: %.2f",
                absolute.eternality, absolute.infinity, absolute.transcendence);
            ImGui::Text("Eternal Entities: %zu", absolute.eternalEntities.size());
        }
        ImGui::PopID();
    }
}

void AbsoluteForeverPanel::RenderForeverExistenceTab() {
    ImGui::Text("Forever Existence Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Foreverness", &s_forevernessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Permanence", &s_permanenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Immortality", &s_immortalityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Realize Existence")) {
        std::string existenceId = Absolute::AbsoluteForeverEngine::RealizeForeverExistence(s_nameBuffer);
        Absolute::AbsoluteForeverEngine::AmplifyForeverness(existenceId, s_forevernessInput);
        Absolute::AbsoluteForeverEngine::StrengthenPermanence(existenceId, s_permanenceInput);
        Absolute::AbsoluteForeverEngine::AchieveImmortality(existenceId, s_immortalityInput);
        OnExistenceRealized(existenceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Realized Existences:");
    auto existences = Absolute::AbsoluteForeverEngine::GetAllExistences();
    for (const auto& existence : existences) {
        ImGui::PushID(existence.existenceId.c_str());
        if (ImGui::Selectable(existence.name.c_str(), s_selectedExistenceId == existence.existenceId)) {
            s_selectedExistenceId = existence.existenceId;
        }
        ImGui::SameLine();
        if (existence.isForever) {
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "[FOREVER]");
        }
        if (s_selectedExistenceId == existence.existenceId) {
            ImGui::Text("Foreverness: %.2f | Permanence: %.2f | Immortality: %.2f",
                existence.foreverness, existence.permanence, existence.immortality);
            if (!existence.isForever && ImGui::Button("Declare Forever")) {
                Absolute::AbsoluteForeverEngine::DeclareForever(existence.existenceId);
            }
        }
        ImGui::PopID();
    }
}

void AbsoluteForeverPanel::RenderInfiniteAbsoluteTab() {
    ImGui::Text("Infinite Absolute Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Infinity", &s_infinityAbsoluteInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Boundlessness", &s_boundlessnessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Limitlessness", &s_limitlessnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Discover Infinite")) {
        std::string infiniteId = Absolute::AbsoluteForeverEngine::DiscoverInfiniteAbsolute(s_nameBuffer);
        Absolute::AbsoluteForeverEngine::AmplifyInfinity(infiniteId, s_infinityAbsoluteInput);
        Absolute::AbsoluteForeverEngine::ExpandBoundlessness(infiniteId, s_boundlessnessInput);
        Absolute::AbsoluteForeverEngine::IncreaseLimitlessness(infiniteId, s_limitlessnessInput);
        OnInfiniteDiscovered(infiniteId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Discovered Infinites:");
    auto infinites = Absolute::AbsoluteForeverEngine::GetAllInfinites();
    for (const auto& infinite : infinites) {
        ImGui::PushID(infinite.infiniteId.c_str());
        if (ImGui::Selectable(infinite.name.c_str(), s_selectedInfiniteId == infinite.infiniteId)) {
            s_selectedInfiniteId = infinite.infiniteId;
        }
        if (s_selectedInfiniteId == infinite.infiniteId) {
            ImGui::Text("Infinity: %.2f | Boundlessness: %.2f | Limitlessness: %.2f",
                infinite.infinity, infinite.boundlessness, infinite.limitlessness);
            ImGui::Text("Infinite Entities: %zu", infinite.infiniteEntities.size());
        }
        ImGui::PopID();
    }
}

void AbsoluteForeverPanel::RenderAbsoluteMetricsTab() {
    ImGui::Text("Absolute Metrics");
    ImGui::Separator();
    
    auto metrics = Absolute::AbsoluteForeverEngine::GetAbsoluteMetrics();
    
    ImGui::Text("Structure Count: %d", metrics["structureCount"].get<int>());
    ImGui::Text("Perpetuity Count: %d", metrics["perpetuityCount"].get<int>());
    ImGui::Text("Absolute Count: %d", metrics["absoluteCount"].get<int>());
    ImGui::Text("Existence Count: %d", metrics["existenceCount"].get<int>());
    ImGui::Text("Infinite Count: %d", metrics["infiniteCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Absoluteness: %.4f", metrics["totalAbsoluteness"].get<float>());
    ImGui::Text("Average Perpetuation: %.4f", metrics["averagePerpetuation"].get<float>());
    ImGui::Text("Ultimate Perpetuities: %d", metrics["ultimatePerpetuities"].get<int>());
    ImGui::Text("Forever Existences: %d", metrics["foreverExistences"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Absolute::AbsoluteForeverLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Absolute Report")) {
        auto report = Absolute::AbsoluteForeverEngine::GenerateAbsoluteReport();
        // Export logic would go here
    }
}

void AbsoluteForeverPanel::RenderAbsoluteVisualizationTab() {
    ImGui::Text("Absolute Visualization");
    ImGui::Separator();
    
    // Draw a representation of absolute forever
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(10, 0, 20, 255));
    
    // Draw absolute structures as crystalline forms
    auto structures = Absolute::AbsoluteForeverEngine::GetAllStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 70.0f + structure.absoluteness * 60.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 10.0f + structure.eternality * 15.0f;
        
        // Crystal glow effect
        for (int i = 4; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 5, IM_COL32(200, 100, 255, 40 - i * 8), 6);
        }
        // Core crystal
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 150, 255, 255), 6);
        
        // Label
        draw_list->AddText(ImVec2(x - 30, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw forever existences as pulsing rings
    auto existences = Absolute::AbsoluteForeverEngine::GetAllExistences();
    int existenceIdx = 0;
    for (const auto& existence : existences) {
        float baseRadius = 30.0f + existenceIdx * 20.0f;
        float pulse = (std::sin(ImGui::GetTime() * 2.0f + existenceIdx) + 1.0f) * 0.5f;
        float radius = baseRadius + pulse * 10.0f;
        float thickness = 2.0f + existence.foreverness * 3.0f;
        ImU32 color = existence.isForever ? IM_COL32(0, 255, 150, 200) : IM_COL32(150, 150, 150, 100);
        
        draw_list->AddCircle(ImVec2(centerX, centerY), radius, color, 64, thickness);
        existenceIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Absolute Event Log:");
    ImGui::BeginChild("AbsoluteEvents", ImVec2(0, 150), true);
    for (auto it = s_absoluteEvents.rbegin(); it != s_absoluteEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
