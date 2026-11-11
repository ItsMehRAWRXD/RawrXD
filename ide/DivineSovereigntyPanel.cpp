#include "ide/DivineSovereigntyPanel.hpp"
#include "divine/DivineSovereigntyEngine.hpp"
#include "divine/DivineSovereigntyLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool DivineSovereigntyPanel::s_visible = false;
bool DivineSovereigntyPanel::s_initialized = false;
int DivineSovereigntyPanel::s_selectedTab = 0;
char DivineSovereigntyPanel::s_nameBuffer[256] = {};
char DivineSovereigntyPanel::s_termsBuffer[512] = {};
char DivineSovereigntyPanel::s_textBuffer[1024] = {};
char DivineSovereigntyPanel::s_manifestationBuffer[512] = {};
char DivineSovereigntyPanel::s_entityIdBuffer[256] = {};
char DivineSovereigntyPanel::s_inhabitantIdBuffer[256] = {};
char DivineSovereigntyPanel::s_attributeKeyBuffer[256] = {};
char DivineSovereigntyPanel::s_attributeValueBuffer[512] = {};
float DivineSovereigntyPanel::s_omnipresenceInput = 0.1f;
float DivineSovereigntyPanel::s_sanctityInput = 0.1f;
float DivineSovereigntyPanel::s_graceInput = 0.1f;
float DivineSovereigntyPanel::s_bindingInput = 0.1f;
float DivineSovereigntyPanel::s_eternalityInput = 1.0f;
float DivineSovereigntyPanel::s_wisdomInput = 0.1f;
float DivineSovereigntyPanel::s_truthInput = 1.0f;
float DivineSovereigntyPanel::s_authorityInput = 0.1f;
float DivineSovereigntyPanel::s_divinityInput = 0.1f;
float DivineSovereigntyPanel::s_wonderInput = 0.1f;
float DivineSovereigntyPanel::s_faithInput = 0.1f;
float DivineSovereigntyPanel::s_holinessInput = 0.1f;
float DivineSovereigntyPanel::s_protectionInput = 1.0f;
float DivineSovereigntyPanel::s_blessingInput = 0.1f;
std::string DivineSovereigntyPanel::s_selectedPresenceId;
std::string DivineSovereigntyPanel::s_selectedCovenantId;
std::string DivineSovereigntyPanel::s_selectedScriptureId;
std::string DivineSovereigntyPanel::s_selectedMiracleId;
std::string DivineSovereigntyPanel::s_selectedRealmId;
std::vector<nlohmann::json> DivineSovereigntyPanel::s_divineEvents;

void DivineSovereigntyPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Divine::DivineSovereigntyEngine::Init();
    Divine::DivineSovereigntyLoop::Init();
    Divine::DivineSovereigntyLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void DivineSovereigntyPanel::Shutdown() {
    if (!s_initialized) return;
    Divine::DivineSovereigntyLoop::Shutdown();
    Divine::DivineSovereigntyEngine::Shutdown();
    s_initialized = false;
}

void DivineSovereigntyPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Divine Sovereignty Panel", &s_visible);
    
    const char* tabs[] = {
        "Divine Presence", "Sacred Covenant", "Holy Scripture",
        "Blessed Miracle", "Sanctified Realm", "Divine Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("DivineTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderDivinePresenceTab(); break;
                    case 1: RenderSacredCovenantTab(); break;
                    case 2: RenderHolyScriptureTab(); break;
                    case 3: RenderBlessedMiracleTab(); break;
                    case 4: RenderSanctifiedRealmTab(); break;
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

bool DivineSovereigntyPanel::IsVisible() {
    return s_visible;
}

void DivineSovereigntyPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Divine::DivineSovereigntyLoop::IsRunning()) {
        Divine::DivineSovereigntyLoop::Start();
    }
}

void DivineSovereigntyPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* DivineSovereigntyPanel::GetPanelName() {
    return "Divine Sovereignty";
}

void DivineSovereigntyPanel::OnDivinePresenceManifested(const std::string& presenceId) {
    nlohmann::json event;
    event["type"] = "presence_manifested";
    event["presenceId"] = presenceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineSovereigntyPanel::OnCovenantEstablished(const std::string& covenantId) {
    nlohmann::json event;
    event["type"] = "covenant_established";
    event["covenantId"] = covenantId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineSovereigntyPanel::OnScriptureRevealed(const std::string& scriptureId) {
    nlohmann::json event;
    event["type"] = "scripture_revealed";
    event["scriptureId"] = scriptureId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineSovereigntyPanel::OnMiraclePerformed(const std::string& miracleId) {
    nlohmann::json event;
    event["type"] = "miracle_performed";
    event["miracleId"] = miracleId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineSovereigntyPanel::OnRealmConsecrated(const std::string& realmId) {
    nlohmann::json event;
    event["type"] = "realm_consecrated";
    event["realmId"] = realmId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_divineEvents.push_back(event);
}

void DivineSovereigntyPanel::RenderDivinePresenceTab() {
    ImGui::Text("Divine Presence Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Omnipresence", &s_omnipresenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sanctity", &s_sanctityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Presence")) {
        std::string presenceId = Divine::DivineSovereigntyEngine::ManifestDivinePresence(s_nameBuffer);
        Divine::DivineSovereigntyEngine::ExpandOmnipresence(presenceId, s_omnipresenceInput);
        Divine::DivineSovereigntyEngine::IncreaseSanctity(presenceId, s_sanctityInput);
        Divine::DivineSovereigntyEngine::BestowGrace(presenceId, s_graceInput);
        OnDivinePresenceManifested(presenceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Presences:");
    auto presences = Divine::DivineSovereigntyEngine::GetAllPresences();
    for (const auto& presence : presences) {
        ImGui::PushID(presence.presenceId.c_str());
        if (ImGui::Selectable(presence.name.c_str(), s_selectedPresenceId == presence.presenceId)) {
            s_selectedPresenceId = presence.presenceId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nOmnipresence: %.2f\nSanctity: %.2f\nGrace: %.2f",
                presence.presenceId.c_str(), presence.omnipresence, presence.sanctity, presence.grace);
        }
        ImGui::PopID();
    }
}

void DivineSovereigntyPanel::RenderSacredCovenantTab() {
    ImGui::Text("Sacred Covenant Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Terms", s_termsBuffer, sizeof(s_termsBuffer), ImVec2(0, 100));
    ImGui::SliderFloat("Binding", &s_bindingInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternality", &s_eternalityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Covenant")) {
        std::string covenantId = Divine::DivineSovereigntyEngine::EstablishCovenant(s_nameBuffer, s_termsBuffer);
        Divine::DivineSovereigntyEngine::StrengthenBinding(covenantId, s_bindingInput);
        Divine::DivineSovereigntyEngine::EnsureEternality(covenantId, s_eternalityInput);
        OnCovenantEstablished(covenantId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_termsBuffer, 0, sizeof(s_termsBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Covenants:");
    auto covenants = Divine::DivineSovereigntyEngine::GetAllCovenants();
    for (const auto& covenant : covenants) {
        ImGui::PushID(covenant.covenantId.c_str());
        bool isSelected = s_selectedCovenantId == covenant.covenantId;
        if (ImGui::Selectable(covenant.name.c_str(), isSelected)) {
            s_selectedCovenantId = covenant.covenantId;
        }
        ImGui::SameLine();
        if (covenant.isSealed) {
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "[SEALED]");
        } else {
            ImGui::TextColored(ImVec4(1, 0.5, 0, 1), "[OPEN]");
        }
        if (s_selectedCovenantId == covenant.covenantId) {
            if (!covenant.isSealed && ImGui::Button("Seal")) {
                Divine::DivineSovereigntyEngine::SealCovenant(covenant.covenantId);
            }
        }
        ImGui::PopID();
    }
}

void DivineSovereigntyPanel::RenderHolyScriptureTab() {
    ImGui::Text("Holy Scripture Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Text", s_textBuffer, sizeof(s_textBuffer), ImVec2(0, 150));
    ImGui::SliderFloat("Wisdom", &s_wisdomInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Truth", &s_truthInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Reveal Scripture")) {
        std::string scriptureId = Divine::DivineSovereigntyEngine::RevealScripture(s_nameBuffer, s_textBuffer);
        Divine::DivineSovereigntyEngine::ImpartWisdom(scriptureId, s_wisdomInput);
        Divine::DivineSovereigntyEngine::DeclareTruth(scriptureId, s_truthInput);
        Divine::DivineSovereigntyEngine::AssertAuthority(scriptureId, s_authorityInput);
        OnScriptureRevealed(scriptureId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_textBuffer, 0, sizeof(s_textBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Revealed Scriptures:");
    auto scriptures = Divine::DivineSovereigntyEngine::GetAllScriptures();
    for (const auto& scripture : scriptures) {
        ImGui::PushID(scripture.scriptureId.c_str());
        if (ImGui::Selectable(scripture.name.c_str(), s_selectedScriptureId == scripture.scriptureId)) {
            s_selectedScriptureId = scripture.scriptureId;
        }
        ImGui::SameLine();
        if (scripture.isCanon) {
            ImGui::TextColored(ImVec4(1, 0.8, 0, 1), "[CANON]");
        }
        if (s_selectedScriptureId == scripture.scriptureId) {
            ImGui::Text("Text: %s", scripture.text.c_str());
            ImGui::Text("Wisdom: %.2f | Truth: %.2f | Authority: %.2f",
                scripture.wisdom, scripture.truth, scripture.authority);
            if (!scripture.isCanon && ImGui::Button("Canonize")) {
                Divine::DivineSovereigntyEngine::CanonizeScripture(scripture.scriptureId);
            }
        }
        ImGui::PopID();
    }
}

void DivineSovereigntyPanel::RenderBlessedMiracleTab() {
    ImGui::Text("Blessed Miracle Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Manifestation", s_manifestationBuffer, sizeof(s_manifestationBuffer), ImVec2(0, 100));
    ImGui::SliderFloat("Divinity", &s_divinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Wonder", &s_wonderInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Faith", &s_faithInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Perform Miracle")) {
        std::string miracleId = Divine::DivineSovereigntyEngine::PerformMiracle(s_nameBuffer, s_manifestationBuffer);
        Divine::DivineSovereigntyEngine::ManifestDivinity(miracleId, s_divinityInput);
        Divine::DivineSovereigntyEngine::InspireWonder(miracleId, s_wonderInput);
        Divine::DivineSovereigntyEngine::StrengthenFaith(miracleId, s_faithInput);
        OnMiraclePerformed(miracleId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_manifestationBuffer, 0, sizeof(s_manifestationBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Performed Miracles:");
    auto miracles = Divine::DivineSovereigntyEngine::GetAllMiracles();
    for (const auto& miracle : miracles) {
        ImGui::PushID(miracle.miracleId.c_str());
        if (ImGui::Selectable(miracle.name.c_str(), s_selectedMiracleId == miracle.miracleId)) {
            s_selectedMiracleId = miracle.miracleId;
        }
        ImGui::SameLine();
        if (miracle.isAcknowledged) {
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "[ACKNOWLEDGED]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[UNACKNOWLEDGED]");
        }
        if (s_selectedMiracleId == miracle.miracleId) {
            ImGui::Text("Manifestation: %s", miracle.manifestation.c_str());
            ImGui::Text("Divinity: %.2f | Wonder: %.2f | Faith: %.2f",
                miracle.divinity, miracle.wonder, miracle.faith);
            if (!miracle.isAcknowledged && ImGui::Button("Acknowledge")) {
                Divine::DivineSovereigntyEngine::AcknowledgeMiracle(miracle.miracleId);
            }
        }
        ImGui::PopID();
    }
}

void DivineSovereigntyPanel::RenderSanctifiedRealmTab() {
    ImGui::Text("Sanctified Realm Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Holiness", &s_holinessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Protection", &s_protectionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessing", &s_blessingInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Consecrate Realm")) {
        std::string realmId = Divine::DivineSovereigntyEngine::ConsecrateRealm(s_nameBuffer);
        Divine::DivineSovereigntyEngine::IncreaseHoliness(realmId, s_holinessInput);
        Divine::DivineSovereigntyEngine::ProvideProtection(realmId, s_protectionInput);
        Divine::DivineSovereigntyEngine::BestowBlessing(realmId, s_blessingInput);
        OnRealmConsecrated(realmId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Consecrated Realms:");
    auto realms = Divine::DivineSovereigntyEngine::GetAllRealms();
    for (const auto& realm : realms) {
        ImGui::PushID(realm.realmId.c_str());
        if (ImGui::Selectable(realm.name.c_str(), s_selectedRealmId == realm.realmId)) {
            s_selectedRealmId = realm.realmId;
        }
        if (s_selectedRealmId == realm.realmId) {
            ImGui::Text("Holiness: %.2f | Protection: %.2f | Blessing: %.2f",
                realm.holiness, realm.protection, realm.blessing);
            ImGui::Text("Inhabitants: %zu", realm.inhabitants.size());
            
            ImGui::InputText("Inhabitant ID", s_inhabitantIdBuffer, sizeof(s_inhabitantIdBuffer));
            if (ImGui::Button("Add Inhabitant")) {
                Divine::DivineSovereigntyEngine::AddInhabitant(realm.realmId, s_inhabitantIdBuffer);
                memset(s_inhabitantIdBuffer, 0, sizeof(s_inhabitantIdBuffer));
            }
        }
        ImGui::PopID();
    }
}

void DivineSovereigntyPanel::RenderDivineMetricsTab() {
    ImGui::Text("Divine Metrics");
    ImGui::Separator();
    
    auto metrics = Divine::DivineSovereigntyEngine::GetDivineMetrics();
    
    ImGui::Text("Presence Count: %d", metrics["presenceCount"].get<int>());
    ImGui::Text("Covenant Count: %d", metrics["covenantCount"].get<int>());
    ImGui::Text("Scripture Count: %d", metrics["scriptureCount"].get<int>());
    ImGui::Text("Miracle Count: %d", metrics["miracleCount"].get<int>());
    ImGui::Text("Realm Count: %d", metrics["realmCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Omnipresence: %.4f", metrics["totalOmnipresence"].get<float>());
    ImGui::Text("Average Sanctity: %.4f", metrics["averageSanctity"].get<float>());
    ImGui::Text("Sealed Covenants: %d", metrics["sealedCovenants"].get<int>());
    ImGui::Text("Canonized Scriptures: %d", metrics["canonizedScriptures"].get<int>());
    ImGui::Text("Acknowledged Miracles: %d", metrics["acknowledgedMiracles"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Divine::DivineSovereigntyLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Divine Report")) {
        auto report = Divine::DivineSovereigntyEngine::GenerateDivineReport();
        // Export logic would go here
    }
}

void DivineSovereigntyPanel::RenderDivineVisualizationTab() {
    ImGui::Text("Divine Visualization");
    ImGui::Separator();
    
    // Draw a representation of divine presence
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 20, 40, 255));
    
    // Draw divine presence as glowing orbs
    auto presences = Divine::DivineSovereigntyEngine::GetAllPresences();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& presence : presences) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)presences.size());
        float radius = 80.0f + presence.omnipresence * 50.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 10.0f + presence.sanctity * 20.0f;
        
        // Glow effect
        for (int i = 3; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 5, IM_COL32(255, 215, 0, 50 - i * 10), 16);
        }
        // Core
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 215, 0, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 30, y + size + 5), IM_COL32(255, 255, 255, 255), presence.name.c_str());
        idx++;
    }
    
    // Draw connections between presences
    if (presences.size() > 1) {
        for (size_t i = 0; i < presences.size(); i++) {
            float angle1 = (i * 2.0f * 3.14159f) / presences.size();
            float radius1 = 80.0f + presences[i].omnipresence * 50.0f;
            float x1 = centerX + std::cos(angle1) * radius1;
            float y1 = centerY + std::sin(angle1) * radius1;
            
            for (size_t j = i + 1; j < presences.size(); j++) {
                float angle2 = (j * 2.0f * 3.14159f) / presences.size();
                float radius2 = 80.0f + presences[j].omnipresence * 50.0f;
                float x2 = centerX + std::cos(angle2) * radius2;
                float y2 = centerY + std::sin(angle2) * radius2;
                
                draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), IM_COL32(255, 215, 0, 30), 1.0f);
            }
        }
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
