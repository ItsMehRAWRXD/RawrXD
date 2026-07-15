#include "ide/TranscendentUnityPanel.hpp"
#include "transcendent/TranscendentUnityEngine.hpp"
#include "transcendent/TranscendentUnityLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool TranscendentUnityPanel::s_visible = false;
bool TranscendentUnityPanel::s_initialized = false;
int TranscendentUnityPanel::s_selectedTab = 0;
char TranscendentUnityPanel::s_nameBuffer[256] = {};
char TranscendentUnityPanel::s_entityIdBuffer[256] = {};
char TranscendentUnityPanel::s_attributeKeyBuffer[256] = {};
char TranscendentUnityPanel::s_attributeValueBuffer[512] = {};
float TranscendentUnityPanel::s_transcendenceInput = 0.1f;
float TranscendentUnityPanel::s_unityInput = 0.1f;
float TranscendentUnityPanel::s_harmonyInput = 0.1f;
float TranscendentUnityPanel::s_balanceInput = 0.1f;
float TranscendentUnityPanel::s_synthesisInput = 0.1f;
float TranscendentUnityPanel::s_unityTranscendentInput = 0.1f;
float TranscendentUnityPanel::s_transcendenceUnityInput = 0.1f;
float TranscendentUnityPanel::s_cohesionInput = 0.1f;
float TranscendentUnityPanel::s_onenessInput = 0.1f;
float TranscendentUnityPanel::s_harmonyTranscendentInput = 0.1f;
float TranscendentUnityPanel::s_transcendenceHarmonyInput = 0.1f;
float TranscendentUnityPanel::s_resonanceInput = 0.1f;
float TranscendentUnityPanel::s_alignmentInput = 0.1f;
float TranscendentUnityPanel::s_balanceTranscendentInput = 0.1f;
float TranscendentUnityPanel::s_transcendenceBalanceInput = 0.1f;
float TranscendentUnityPanel::s_equilibriumInput = 0.1f;
float TranscendentUnityPanel::s_stabilityInput = 0.1f;
float TranscendentUnityPanel::s_synthesisTranscendentInput = 0.1f;
float TranscendentUnityPanel::s_transcendenceSynthesisInput = 0.1f;
float TranscendentUnityPanel::s_integrationInput = 0.1f;
float TranscendentUnityPanel::s_fusionInput = 0.1f;
std::string TranscendentUnityPanel::s_selectedTranscendentId;
std::string TranscendentUnityPanel::s_selectedUnityId;
std::string TranscendentUnityPanel::s_selectedHarmonyId;
std::string TranscendentUnityPanel::s_selectedBalanceId;
std::string TranscendentUnityPanel::s_selectedSynthesisId;
std::vector<nlohmann::json> TranscendentUnityPanel::s_transcendentEvents;

void TranscendentUnityPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    TranscendentUnity::TranscendentUnityEngine::Init();
    TranscendentUnity::TranscendentUnityLoop::Init();
    TranscendentUnity::TranscendentUnityLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void TranscendentUnityPanel::Shutdown() {
    if (!s_initialized) return;
    TranscendentUnity::TranscendentUnityLoop::Shutdown();
    TranscendentUnity::TranscendentUnityEngine::Shutdown();
    s_initialized = false;
}

void TranscendentUnityPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Transcendent Unity Panel", &s_visible);
    
    const char* tabs[] = {
        "Transcendent Structure", "Unity Transcendent", "Harmony Transcendent",
        "Balance Transcendent", "Synthesis Transcendent", "Transcendent Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("TranscendentTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderTranscendentStructureTab(); break;
                    case 1: RenderUnityTranscendentTab(); break;
                    case 2: RenderHarmonyTranscendentTab(); break;
                    case 3: RenderBalanceTranscendentTab(); break;
                    case 4: RenderSynthesisTranscendentTab(); break;
                    case 5: RenderTranscendentMetricsTab(); break;
                    case 6: RenderTranscendentVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool TranscendentUnityPanel::IsVisible() {
    return s_visible;
}

void TranscendentUnityPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !TranscendentUnity::TranscendentUnityLoop::IsRunning()) {
        TranscendentUnity::TranscendentUnityLoop::Start();
    }
}

void TranscendentUnityPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* TranscendentUnityPanel::GetPanelName() {
    return "Transcendent Unity";
}

void TranscendentUnityPanel::OnTranscendentStructureCreated(const std::string& transcendentId) {
    nlohmann::json event;
    event["type"] = "transcendent_structure_created";
    event["transcendentId"] = transcendentId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_transcendentEvents.push_back(event);
}

void TranscendentUnityPanel::OnUnityEstablished(const std::string& unityId) {
    nlohmann::json event;
    event["type"] = "unity_established";
    event["unityId"] = unityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_transcendentEvents.push_back(event);
}

void TranscendentUnityPanel::OnHarmonyCultivated(const std::string& harmonyId) {
    nlohmann::json event;
    event["type"] = "harmony_cultivated";
    event["harmonyId"] = harmonyId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_transcendentEvents.push_back(event);
}

void TranscendentUnityPanel::OnBalanceEstablished(const std::string& balanceId) {
    nlohmann::json event;
    event["type"] = "balance_established";
    event["balanceId"] = balanceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_transcendentEvents.push_back(event);
}

void TranscendentUnityPanel::OnSynthesisAchieved(const std::string& synthesisId) {
    nlohmann::json event;
    event["type"] = "synthesis_achieved";
    event["synthesisId"] = synthesisId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_transcendentEvents.push_back(event);
}

void TranscendentUnityPanel::RenderTranscendentStructureTab() {
    ImGui::Text("Transcendent Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Transcendence", &s_transcendenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Unity", &s_unityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Harmony", &s_harmonyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Balance", &s_balanceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Synthesis", &s_synthesisInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string transcendentId = TranscendentUnity::TranscendentUnityEngine::CreateTranscendentUnityStructure(s_nameBuffer);
        TranscendentUnity::TranscendentUnityEngine::ElevateTranscendence(transcendentId, s_transcendenceInput);
        TranscendentUnity::TranscendentUnityEngine::ExpandUnity(transcendentId, s_unityInput);
        TranscendentUnity::TranscendentUnityEngine::CultivateHarmony(transcendentId, s_harmonyInput);
        TranscendentUnity::TranscendentUnityEngine::EstablishBalance(transcendentId, s_balanceInput);
        TranscendentUnity::TranscendentUnityEngine::AchieveSynthesis(transcendentId, s_synthesisInput);
        OnTranscendentStructureCreated(transcendentId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = TranscendentUnity::TranscendentUnityEngine::GetAllTranscendentUnityStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.transcendentId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedTranscendentId == structure.transcendentId)) {
            s_selectedTranscendentId = structure.transcendentId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nTranscendence: %.2f\nUnity: %.2f\nHarmony: %.2f\nBalance: %.2f\nSynthesis: %.2f",
                structure.transcendentId.c_str(), structure.transcendence, structure.unity, 
                structure.harmony, structure.balance, structure.synthesis);
        }
        ImGui::PopID();
    }
}

void TranscendentUnityPanel::RenderUnityTranscendentTab() {
    ImGui::Text("Unity Transcendent Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Unity", &s_unityTranscendentInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceUnityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Cohesion", &s_cohesionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Oneness", &s_onenessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Unity")) {
        std::string unityId = TranscendentUnity::TranscendentUnityEngine::CreateUnityTranscendent(s_nameBuffer);
        TranscendentUnity::TranscendentUnityEngine::StrengthenCohesion(unityId, s_cohesionInput);
        TranscendentUnity::TranscendentUnityEngine::RealizeOneness(unityId, s_onenessInput);
        OnUnityEstablished(unityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Unities:");
    auto unities = TranscendentUnity::TranscendentUnityEngine::GetAllUnityTranscendents();
    for (const auto& unity : unities) {
        ImGui::PushID(unity.unityId.c_str());
        bool isSelected = s_selectedUnityId == unity.unityId;
        if (ImGui::Selectable(unity.name.c_str(), isSelected)) {
            s_selectedUnityId = unity.unityId;
        }
        ImGui::SameLine();
        if (unity.isUnified) {
            ImGui::TextColored(ImVec4(0.5f, 1, 0.8f, 1), "[UNIFIED]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[DIVIDED]");
        }
        if (s_selectedUnityId == unity.unityId) {
            if (!unity.isUnified && ImGui::Button("Declare Unified")) {
                TranscendentUnity::TranscendentUnityEngine::DeclareUnified(unity.unityId);
            }
        }
        ImGui::PopID();
    }
}

void TranscendentUnityPanel::RenderHarmonyTranscendentTab() {
    ImGui::Text("Harmony Transcendent Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Harmony", &s_harmonyTranscendentInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceHarmonyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Resonance", &s_resonanceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Alignment", &s_alignmentInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Cultivate Harmony")) {
        std::string harmonyId = TranscendentUnity::TranscendentUnityEngine::CreateHarmonyTranscendent(s_nameBuffer);
        TranscendentUnity::TranscendentUnityEngine::AmplifyResonance(harmonyId, s_resonanceInput);
        TranscendentUnity::TranscendentUnityEngine::PerfectAlignment(harmonyId, s_alignmentInput);
        OnHarmonyCultivated(harmonyId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Cultivated Harmonies:");
    auto harmonies = TranscendentUnity::TranscendentUnityEngine::GetAllHarmonyTranscendents();
    for (const auto& harmony : harmonies) {
        ImGui::PushID(harmony.harmonyId.c_str());
        if (ImGui::Selectable(harmony.name.c_str(), s_selectedHarmonyId == harmony.harmonyId)) {
            s_selectedHarmonyId = harmony.harmonyId;
        }
        if (s_selectedHarmonyId == harmony.harmonyId) {
            ImGui::Text("Harmony: %.2f | Transcendence: %.2f | Resonance: %.2f | Alignment: %.2f",
                harmony.harmony, harmony.transcendence, harmony.resonance, harmony.alignment);
        }
        ImGui::PopID();
    }
}

void TranscendentUnityPanel::RenderBalanceTranscendentTab() {
    ImGui::Text("Balance Transcendent Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Balance", &s_balanceTranscendentInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceBalanceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Equilibrium", &s_equilibriumInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Stability", &s_stabilityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Balance")) {
        std::string balanceId = TranscendentUnity::TranscendentUnityEngine::CreateBalanceTranscendent(s_nameBuffer);
        TranscendentUnity::TranscendentUnityEngine::RestoreEquilibrium(balanceId, s_equilibriumInput);
        TranscendentUnity::TranscendentUnityEngine::EnsureStability(balanceId, s_stabilityInput);
        OnBalanceEstablished(balanceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Balances:");
    auto balances = TranscendentUnity::TranscendentUnityEngine::GetAllBalanceTranscendents();
    for (const auto& balance : balances) {
        ImGui::PushID(balance.balanceId.c_str());
        bool isSelected = s_selectedBalanceId == balance.balanceId;
        if (ImGui::Selectable(balance.name.c_str(), isSelected)) {
            s_selectedBalanceId = balance.balanceId;
        }
        ImGui::SameLine();
        if (balance.isBalanced) {
            ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "[BALANCED]");
        }
        if (s_selectedBalanceId == balance.balanceId) {
            ImGui::Text("Balance: %.2f | Transcendence: %.2f | Equilibrium: %.2f | Stability: %.2f",
                balance.balance, balance.transcendence, balance.equilibrium, balance.stability);
            if (!balance.isBalanced && ImGui::Button("Declare Balanced")) {
                TranscendentUnity::TranscendentUnityEngine::DeclareBalanced(balance.balanceId);
            }
        }
        ImGui::PopID();
    }
}

void TranscendentUnityPanel::RenderSynthesisTranscendentTab() {
    ImGui::Text("Synthesis Transcendent Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Synthesis", &s_synthesisTranscendentInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Transcendence", &s_transcendenceSynthesisInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Integration", &s_integrationInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Fusion", &s_fusionInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Achieve Synthesis")) {
        std::string synthesisId = TranscendentUnity::TranscendentUnityEngine::CreateSynthesisTranscendent(s_nameBuffer);
        TranscendentUnity::TranscendentUnityEngine::DeepenIntegration(synthesisId, s_integrationInput);
        TranscendentUnity::TranscendentUnityEngine::CatalyzeFusion(synthesisId, s_fusionInput);
        OnSynthesisAchieved(synthesisId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Achieved Syntheses:");
    auto syntheses = TranscendentUnity::TranscendentUnityEngine::GetAllSynthesisTranscendents();
    for (const auto& synthesis : syntheses) {
        ImGui::PushID(synthesis.synthesisId.c_str());
        if (ImGui::Selectable(synthesis.name.c_str(), s_selectedSynthesisId == synthesis.synthesisId)) {
            s_selectedSynthesisId = synthesis.synthesisId;
        }
        if (s_selectedSynthesisId == synthesis.synthesisId) {
            ImGui::Text("Synthesis: %.2f | Transcendence: %.2f | Integration: %.2f | Fusion: %.2f",
                synthesis.synthesis, synthesis.transcendence, synthesis.integration, synthesis.fusion);
        }
        ImGui::PopID();
    }
}

void TranscendentUnityPanel::RenderTranscendentMetricsTab() {
    ImGui::Text("Transcendent Unity Metrics");
    ImGui::Separator();
    
    auto metrics = TranscendentUnity::TranscendentUnityEngine::GetTranscendentUnityMetrics();
    
    ImGui::Text("Transcendent Count: %d", metrics["transcendentCount"].get<int>());
    ImGui::Text("Unity Count: %d", metrics["unityCount"].get<int>());
    ImGui::Text("Harmony Count: %d", metrics["harmonyCount"].get<int>());
    ImGui::Text("Balance Count: %d", metrics["balanceCount"].get<int>());
    ImGui::Text("Synthesis Count: %d", metrics["synthesisCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Transcendence: %.4f", metrics["totalTranscendence"].get<float>());
    ImGui::Text("Average Transcendence: %.4f", metrics["averageTranscendence"].get<float>());
    ImGui::Text("Transcendent Transcendents: %d", metrics["transcendentTranscendents"].get<int>());
    ImGui::Text("Total Unity: %.4f", metrics["totalUnity"].get<float>());
    ImGui::Text("Unified Unities: %d", metrics["unifiedUnities"].get<int>());
    ImGui::Text("Balanced Balances: %d", metrics["balancedBalances"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", TranscendentUnity::TranscendentUnityLoop::GetTickCount());
    ImGui::Text("Loop FPS: %.1f", TranscendentUnity::TranscendentUnityLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Transcendent Report")) {
        auto report = TranscendentUnity::TranscendentUnityEngine::GenerateTranscendentUnityReport();
        // Export logic would go here
    }
}

void TranscendentUnityPanel::RenderTranscendentVisualizationTab() {
    ImGui::Text("Transcendent Unity Visualization");
    ImGui::Separator();
    
    // Draw a representation of transcendent unity
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 25, 40, 255));
    
    // Draw transcendent structures as luminous orbs
    auto structures = TranscendentUnity::TranscendentUnityEngine::GetAllTranscendentUnityStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.transcendence * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.unity * 10.0f;
        
        // Transcendent glow effect (cyan/white)
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(200, 255, 255, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(220, 255, 255, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw unity transcendents as unified rays
    auto unities = TranscendentUnity::TranscendentUnityEngine::GetAllUnityTranscendents();
    int unityIdx = 0;
    for (const auto& unity : unities) {
        float angle = (unityIdx * 2.0f * 3.14159f) / std::max(1, (int)unities.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + unity.cohesion * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = unity.isUnified ? 
            IM_COL32(150, 255, 200, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + unity.unity * 3.0f);
        unityIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Transcendent Event Log:");
    ImGui::BeginChild("TranscendentEvents", ImVec2(0, 150), true);
    for (auto it = s_transcendentEvents.rbegin(); it != s_transcendentEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
