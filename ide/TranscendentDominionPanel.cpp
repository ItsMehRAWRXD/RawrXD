#include "ide/TranscendentDominionPanel.hpp"
#include "dominion/TranscendentDominionEngine.hpp"
#include "dominion/TranscendentDominionLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool TranscendentDominionPanel::s_visible = false;
bool TranscendentDominionPanel::s_initialized = false;
int TranscendentDominionPanel::s_selectedTab = 0;
char TranscendentDominionPanel::s_nameBuffer[256] = {};
char TranscendentDominionPanel::s_jurisdictionBuffer[512] = {};
char TranscendentDominionPanel::s_edictBuffer[1024] = {};
char TranscendentDominionPanel::s_realityIdBuffer[256] = {};
char TranscendentDominionPanel::s_entityIdBuffer[256] = {};
char TranscendentDominionPanel::s_beingIdBuffer[256] = {};
char TranscendentDominionPanel::s_attributeKeyBuffer[256] = {};
char TranscendentDominionPanel::s_attributeValueBuffer[512] = {};
int TranscendentDominionPanel::s_dimensionCountInput = 3;
float TranscendentDominionPanel::s_authorityInput = 0.1f;
float TranscendentDominionPanel::s_dominionInput = 0.1f;
float TranscendentDominionPanel::s_majestyInput = 0.1f;
float TranscendentDominionPanel::s_dimensionalReachInput = 0.1f;
float TranscendentDominionPanel::s_temporalScopeInput = 1.0f;
float TranscendentDominionPanel::s_spatialScopeInput = 1.0f;
float TranscendentDominionPanel::s_enforcementInput = 0.1f;
float TranscendentDominionPanel::s_complianceInput = 0.1f;
float TranscendentDominionPanel::s_orderInput = 1.0f;
float TranscendentDominionPanel::s_universalityInput = 0.1f;
float TranscendentDominionPanel::s_immutabilityInput = 1.0f;
float TranscendentDominionPanel::s_transcendenceInput = 0.1f;
float TranscendentDominionPanel::s_infinityInput = 0.1f;
float TranscendentDominionPanel::s_eternityInput = 1.0f;
std::string TranscendentDominionPanel::s_selectedSovereignId;
std::string TranscendentDominionPanel::s_selectedAuthorityId;
std::string TranscendentDominionPanel::s_selectedGovernanceId;
std::string TranscendentDominionPanel::s_selectedLawId;
std::string TranscendentDominionPanel::s_selectedRealmId;
std::vector<nlohmann::json> TranscendentDominionPanel::s_dominionEvents;

void TranscendentDominionPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Dominion::TranscendentDominionEngine::Init();
    Dominion::TranscendentDominionLoop::Init();
    Dominion::TranscendentDominionLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void TranscendentDominionPanel::Shutdown() {
    if (!s_initialized) return;
    Dominion::TranscendentDominionLoop::Shutdown();
    Dominion::TranscendentDominionEngine::Shutdown();
    s_initialized = false;
}

void TranscendentDominionPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Transcendent Dominion Panel", &s_visible);
    
    const char* tabs[] = {
        "Reality Sovereign", "Dimensional Authority", "Existence Governance",
        "Cosmic Law", "Transcendent Realm", "Dominion Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("DominionTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderRealitySovereignTab(); break;
                    case 1: RenderDimensionalAuthorityTab(); break;
                    case 2: RenderExistenceGovernanceTab(); break;
                    case 3: RenderCosmicLawTab(); break;
                    case 4: RenderTranscendentRealmTab(); break;
                    case 5: RenderDominionMetricsTab(); break;
                    case 6: RenderDominionVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool TranscendentDominionPanel::IsVisible() {
    return s_visible;
}

void TranscendentDominionPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !Dominion::TranscendentDominionLoop::IsRunning()) {
        Dominion::TranscendentDominionLoop::Start();
    }
}

void TranscendentDominionPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* TranscendentDominionPanel::GetPanelName() {
    return "Transcendent Dominion";
}

void TranscendentDominionPanel::OnSovereignEnthroned(const std::string& sovereignId) {
    nlohmann::json event;
    event["type"] = "sovereign_enthroned";
    event["sovereignId"] = sovereignId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionEvents.push_back(event);
}

void TranscendentDominionPanel::OnAuthorityEstablished(const std::string& authorityId) {
    nlohmann::json event;
    event["type"] = "authority_established";
    event["authorityId"] = authorityId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionEvents.push_back(event);
}

void TranscendentDominionPanel::OnGovernanceEnacted(const std::string& governanceId) {
    nlohmann::json event;
    event["type"] = "governance_enacted";
    event["governanceId"] = governanceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionEvents.push_back(event);
}

void TranscendentDominionPanel::OnLawDecreed(const std::string& lawId) {
    nlohmann::json event;
    event["type"] = "law_decreed";
    event["lawId"] = lawId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionEvents.push_back(event);
}

void TranscendentDominionPanel::OnRealmManifested(const std::string& realmId) {
    nlohmann::json event;
    event["type"] = "realm_manifested";
    event["realmId"] = realmId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionEvents.push_back(event);
}

void TranscendentDominionPanel::RenderRealitySovereignTab() {
    ImGui::Text("Reality Sovereign Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Majesty", &s_majestyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Enthrone Sovereign")) {
        std::string sovereignId = Dominion::TranscendentDominionEngine::EnthroneSovereign(s_nameBuffer);
        Dominion::TranscendentDominionEngine::AssertAuthority(sovereignId, s_authorityInput);
        Dominion::TranscendentDominionEngine::ExpandDominion(sovereignId, s_dominionInput);
        Dominion::TranscendentDominionEngine::RadiateMajesty(sovereignId, s_majestyInput);
        OnSovereignEnthroned(sovereignId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Enthroned Sovereigns:");
    auto sovereigns = Dominion::TranscendentDominionEngine::GetAllSovereigns();
    for (const auto& sovereign : sovereigns) {
        ImGui::PushID(sovereign.sovereignId.c_str());
        if (ImGui::Selectable(sovereign.name.c_str(), s_selectedSovereignId == sovereign.sovereignId)) {
            s_selectedSovereignId = sovereign.sovereignId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nAuthority: %.2f\nDominion: %.2f\nMajesty: %.2f",
                sovereign.sovereignId.c_str(), sovereign.authority, sovereign.dominion, sovereign.majesty);
        }
        ImGui::PopID();
    }
}

void TranscendentDominionPanel::RenderDimensionalAuthorityTab() {
    ImGui::Text("Dimensional Authority Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputInt("Dimension Count", &s_dimensionCountInput);
    ImGui::SliderFloat("Dimensional Reach", &s_dimensionalReachInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Temporal Scope", &s_temporalScopeInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Spatial Scope", &s_spatialScopeInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Authority")) {
        std::string authorityId = Dominion::TranscendentDominionEngine::EstablishAuthority(s_nameBuffer, s_dimensionCountInput);
        Dominion::TranscendentDominionEngine::ExtendDimensionalReach(authorityId, s_dimensionalReachInput);
        Dominion::TranscendentDominionEngine::ExpandTemporalScope(authorityId, s_temporalScopeInput);
        Dominion::TranscendentDominionEngine::ExpandSpatialScope(authorityId, s_spatialScopeInput);
        OnAuthorityEstablished(authorityId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Authorities:");
    auto authorities = Dominion::TranscendentDominionEngine::GetAllAuthorities();
    for (const auto& authority : authorities) {
        ImGui::PushID(authority.authorityId.c_str());
        bool isSelected = s_selectedAuthorityId == authority.authorityId;
        if (ImGui::Selectable(authority.name.c_str(), isSelected)) {
            s_selectedAuthorityId = authority.authorityId;
        }
        ImGui::SameLine();
        if (authority.isAbsolute) {
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "[ABSOLUTE]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[LIMITED]");
        }
        if (s_selectedAuthorityId == authority.authorityId) {
            if (!authority.isAbsolute && ImGui::Button("Assert Absolute")) {
                Dominion::TranscendentDominionEngine::AssertAbsoluteAuthority(authority.authorityId);
            }
        }
        ImGui::PopID();
    }
}

void TranscendentDominionPanel::RenderExistenceGovernanceTab() {
    ImGui::Text("Existence Governance Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Jurisdiction", s_jurisdictionBuffer, sizeof(s_jurisdictionBuffer));
    ImGui::SliderFloat("Enforcement", &s_enforcementInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Compliance", &s_complianceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Order", &s_orderInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Enact Governance")) {
        std::string governanceId = Dominion::TranscendentDominionEngine::EnactGovernance(s_nameBuffer, s_jurisdictionBuffer);
        Dominion::TranscendentDominionEngine::StrengthenEnforcement(governanceId, s_enforcementInput);
        Dominion::TranscendentDominionEngine::IncreaseCompliance(governanceId, s_complianceInput);
        Dominion::TranscendentDominionEngine::EstablishOrder(governanceId, s_orderInput);
        OnGovernanceEnacted(governanceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_jurisdictionBuffer, 0, sizeof(s_jurisdictionBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Enacted Governances:");
    auto governances = Dominion::TranscendentDominionEngine::GetAllGovernances();
    for (const auto& governance : governances) {
        ImGui::PushID(governance.governanceId.c_str());
        if (ImGui::Selectable(governance.name.c_str(), s_selectedGovernanceId == governance.governanceId)) {
            s_selectedGovernanceId = governance.governanceId;
        }
        if (s_selectedGovernanceId == governance.governanceId) {
            ImGui::Text("Jurisdiction: %s", governance.jurisdiction.c_str());
            ImGui::Text("Enforcement: %.2f | Compliance: %.2f | Order: %.2f",
                governance.enforcement, governance.compliance, governance.order);
            ImGui::Text("Governed Entities: %zu", governance.governedEntities.size());
        }
        ImGui::PopID();
    }
}

void TranscendentDominionPanel::RenderCosmicLawTab() {
    ImGui::Text("Cosmic Law Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Edict", s_edictBuffer, sizeof(s_edictBuffer), ImVec2(0, 150));
    ImGui::SliderFloat("Universality", &s_universalityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Immutability", &s_immutabilityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Enforcement", &s_enforcementInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Decree Law")) {
        std::string lawId = Dominion::TranscendentDominionEngine::DecreeLaw(s_nameBuffer, s_edictBuffer);
        Dominion::TranscendentDominionEngine::AffirmUniversality(lawId, s_universalityInput);
        Dominion::TranscendentDominionEngine::EnsureImmutability(lawId, s_immutabilityInput);
        Dominion::TranscendentDominionEngine::EnforceLaw(lawId, s_enforcementInput);
        OnLawDecreed(lawId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_edictBuffer, 0, sizeof(s_edictBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Decreed Laws:");
    auto laws = Dominion::TranscendentDominionEngine::GetAllLaws();
    for (const auto& law : laws) {
        ImGui::PushID(law.lawId.c_str());
        if (ImGui::Selectable(law.name.c_str(), s_selectedLawId == law.lawId)) {
            s_selectedLawId = law.lawId;
        }
        ImGui::SameLine();
        if (law.isFundamental) {
            ImGui::TextColored(ImVec4(1, 0.8, 0, 1), "[FUNDAMENTAL]");
        }
        if (s_selectedLawId == law.lawId) {
            ImGui::Text("Edict: %s", law.edict.c_str());
            ImGui::Text("Universality: %.2f | Immutability: %.2f | Enforcement: %.2f",
                law.universality, law.immutability, law.enforcement);
            if (!law.isFundamental && ImGui::Button("Declare Fundamental")) {
                Dominion::TranscendentDominionEngine::DeclareFundamental(law.lawId);
            }
        }
        ImGui::PopID();
    }
}

void TranscendentDominionPanel::RenderTranscendentRealmTab() {
    ImGui::Text("Transcendent Realm Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Transcendence", &s_transcendenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Infinity", &s_infinityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Eternity", &s_eternityInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Manifest Realm")) {
        std::string realmId = Dominion::TranscendentDominionEngine::ManifestRealm(s_nameBuffer);
        Dominion::TranscendentDominionEngine::ElevateTranscendence(realmId, s_transcendenceInput);
        Dominion::TranscendentDominionEngine::ExpandInfinity(realmId, s_infinityInput);
        Dominion::TranscendentDominionEngine::ExtendEternity(realmId, s_eternityInput);
        OnRealmManifested(realmId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Manifested Realms:");
    auto realms = Dominion::TranscendentDominionEngine::GetAllRealms();
    for (const auto& realm : realms) {
        ImGui::PushID(realm.realmId.c_str());
        if (ImGui::Selectable(realm.name.c_str(), s_selectedRealmId == realm.realmId)) {
            s_selectedRealmId = realm.realmId;
        }
        if (s_selectedRealmId == realm.realmId) {
            ImGui::Text("Transcendence: %.2f | Infinity: %.2f | Eternity: %.2f",
                realm.transcendence, realm.infinity, realm.eternity);
            ImGui::Text("Transcendent Beings: %zu", realm.transcendentBeings.size());
            
            ImGui::InputText("Being ID", s_beingIdBuffer, sizeof(s_beingIdBuffer));
            if (ImGui::Button("Welcome Being")) {
                Dominion::TranscendentDominionEngine::WelcomeTranscendentBeing(realm.realmId, s_beingIdBuffer);
                memset(s_beingIdBuffer, 0, sizeof(s_beingIdBuffer));
            }
        }
        ImGui::PopID();
    }
}

void TranscendentDominionPanel::RenderDominionMetricsTab() {
    ImGui::Text("Dominion Metrics");
    ImGui::Separator();
    
    auto metrics = Dominion::TranscendentDominionEngine::GetDominionMetrics();
    
    ImGui::Text("Sovereign Count: %d", metrics["sovereignCount"].get<int>());
    ImGui::Text("Authority Count: %d", metrics["authorityCount"].get<int>());
    ImGui::Text("Governance Count: %d", metrics["governanceCount"].get<int>());
    ImGui::Text("Law Count: %d", metrics["lawCount"].get<int>());
    ImGui::Text("Realm Count: %d", metrics["realmCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Authority: %.4f", metrics["totalAuthority"].get<float>());
    ImGui::Text("Average Dominion: %.4f", metrics["averageDominion"].get<float>());
    ImGui::Text("Absolute Authorities: %d", metrics["absoluteAuthorities"].get<int>());
    ImGui::Text("Fundamental Laws: %d", metrics["fundamentalLaws"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
    ImGui::Text("Loop FPS: %.1f", Dominion::TranscendentDominionLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Dominion Report")) {
        auto report = Dominion::TranscendentDominionEngine::GenerateDominionReport();
        // Export logic would go here
    }
}

void TranscendentDominionPanel::RenderDominionVisualizationTab() {
    ImGui::Text("Dominion Visualization");
    ImGui::Separator();
    
    // Draw a representation of transcendent dominion
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(10, 10, 30, 255));
    
    // Draw reality sovereigns as majestic orbs
    auto sovereigns = Dominion::TranscendentDominionEngine::GetAllSovereigns();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& sovereign : sovereigns) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)sovereigns.size());
        float radius = 80.0f + sovereign.dominion * 50.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 10.0f + sovereign.authority * 20.0f;
        
        // Majesty glow effect
        for (int i = 3; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 5, IM_COL32(138, 43, 226, 50 - i * 10), 16);
        }
        // Core
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(138, 43, 226, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 30, y + size + 5), IM_COL32(255, 255, 255, 255), sovereign.name.c_str());
        idx++;
    }
    
    // Draw cosmic laws as horizontal lines
    auto laws = Dominion::TranscendentDominionEngine::GetAllLaws();
    int lawIdx = 0;
    for (const auto& law : laws) {
        float y = canvas_pos.y + 30 + lawIdx * 25;
        float thickness = 2.0f + law.enforcement * 3.0f;
        ImU32 color = law.isFundamental ? IM_COL32(255, 215, 0, 200) : IM_COL32(100, 100, 150, 150);
        draw_list->AddLine(ImVec2(canvas_pos.x + 20, y), ImVec2(canvas_pos.x + canvas_size.x - 20, y), color, thickness);
        draw_list->AddText(ImVec2(canvas_pos.x + 25, y - 8), IM_COL32(255, 255, 255, 200), law.name.c_str());
        lawIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Dominion Event Log:");
    ImGui::BeginChild("DominionEvents", ImVec2(0, 150), true);
    for (auto it = s_dominionEvents.rbegin(); it != s_dominionEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
