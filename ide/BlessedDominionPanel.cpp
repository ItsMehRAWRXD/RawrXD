#include "ide/BlessedDominionPanel.hpp"
#include "blessed/BlessedDominionEngine.hpp"
#include "blessed/BlessedDominionLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool BlessedDominionPanel::s_visible = false;
bool BlessedDominionPanel::s_initialized = false;
int BlessedDominionPanel::s_selectedTab = 0;
char BlessedDominionPanel::s_nameBuffer[256] = {};
char BlessedDominionPanel::s_entityIdBuffer[256] = {};
char BlessedDominionPanel::s_attributeKeyBuffer[256] = {};
char BlessedDominionPanel::s_attributeValueBuffer[512] = {};
float BlessedDominionPanel::s_blessednessInput = 0.1f;
float BlessedDominionPanel::s_dominionInput = 0.1f;
float BlessedDominionPanel::s_graceInput = 0.1f;
float BlessedDominionPanel::s_favorInput = 0.1f;
float BlessedDominionPanel::s_providenceInput = 0.1f;
float BlessedDominionPanel::s_dominionBlessedInput = 0.1f;
float BlessedDominionPanel::s_blessednessDominionInput = 0.1f;
float BlessedDominionPanel::s_authorityInput = 0.1f;
float BlessedDominionPanel::s_sovereigntyInput = 0.1f;
float BlessedDominionPanel::s_graceBlessedInput = 0.1f;
float BlessedDominionPanel::s_blessednessGraceInput = 0.1f;
float BlessedDominionPanel::s_mercyInput = 0.1f;
float BlessedDominionPanel::s_kindnessInput = 0.1f;
float BlessedDominionPanel::s_favorBlessedInput = 0.1f;
float BlessedDominionPanel::s_blessednessFavorInput = 0.1f;
float BlessedDominionPanel::s_preferenceInput = 0.1f;
float BlessedDominionPanel::s_approvalInput = 0.1f;
float BlessedDominionPanel::s_providenceBlessedInput = 0.1f;
float BlessedDominionPanel::s_blessednessProvidenceInput = 0.1f;
float BlessedDominionPanel::s_guidanceInput = 0.1f;
float BlessedDominionPanel::s_protectionInput = 0.1f;
std::string BlessedDominionPanel::s_selectedBlessedId;
std::string BlessedDominionPanel::s_selectedDominionId;
std::string BlessedDominionPanel::s_selectedGraceId;
std::string BlessedDominionPanel::s_selectedFavorId;
std::string BlessedDominionPanel::s_selectedProvidenceId;
std::vector<nlohmann::json> BlessedDominionPanel::s_blessedEvents;

void BlessedDominionPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    BlessedDominion::BlessedDominionEngine::Init();
    BlessedDominion::BlessedDominionLoop::Init();
    BlessedDominion::BlessedDominionLoop::RegisterTickCallback([]() {
        // Tick callback for panel updates
    });
}

void BlessedDominionPanel::Shutdown() {
    if (!s_initialized) return;
    BlessedDominion::BlessedDominionLoop::Shutdown();
    BlessedDominion::BlessedDominionEngine::Shutdown();
    s_initialized = false;
}

void BlessedDominionPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Blessed Dominion Panel", &s_visible);
    
    const char* tabs[] = {
        "Blessed Structure", "Dominion Blessed", "Grace Blessed",
        "Favor Blessed", "Providence Blessed", "Blessed Metrics", "Visualization"
    };
    
    if (ImGui::BeginTabBar("BlessedTabs")) {
        for (int i = 0; i < 7; i++) {
            if (ImGui::BeginTabItem(tabs[i])) {
                s_selectedTab = i;
                switch (i) {
                    case 0: RenderBlessedStructureTab(); break;
                    case 1: RenderDominionBlessedTab(); break;
                    case 2: RenderGraceBlessedTab(); break;
                    case 3: RenderFavorBlessedTab(); break;
                    case 4: RenderProvidenceBlessedTab(); break;
                    case 5: RenderBlessedMetricsTab(); break;
                    case 6: RenderBlessedVisualizationTab(); break;
                }
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    
    ImGui::End();
}

bool BlessedDominionPanel::IsVisible() {
    return s_visible;
}

void BlessedDominionPanel::SetVisible(bool visible) {
    s_visible = visible;
    if (visible && !BlessedDominion::BlessedDominionLoop::IsRunning()) {
        BlessedDominion::BlessedDominionLoop::Start();
    }
}

void BlessedDominionPanel::ToggleVisibility() {
    SetVisible(!s_visible);
}

const char* BlessedDominionPanel::GetPanelName() {
    return "Blessed Dominion";
}

void BlessedDominionPanel::OnBlessedStructureCreated(const std::string& blessedId) {
    nlohmann::json event;
    event["type"] = "blessed_structure_created";
    event["blessedId"] = blessedId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedDominionPanel::OnDominionEstablished(const std::string& dominionId) {
    nlohmann::json event;
    event["type"] = "dominion_established";
    event["dominionId"] = dominionId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedDominionPanel::OnGraceBestowed(const std::string& graceId) {
    nlohmann::json event;
    event["type"] = "grace_bestowed";
    event["graceId"] = graceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedDominionPanel::OnFavorGranted(const std::string& favorId) {
    nlohmann::json event;
    event["type"] = "favor_granted";
    event["favorId"] = favorId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedDominionPanel::OnProvidenceProvided(const std::string& providenceId) {
    nlohmann::json event;
    event["type"] = "providence_provided";
    event["providenceId"] = providenceId;
    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessedEvents.push_back(event);
}

void BlessedDominionPanel::RenderBlessedStructureTab() {
    ImGui::Text("Blessed Structure Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Blessedness", &s_blessednessInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Dominion", &s_dominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Grace", &s_graceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Favor", &s_favorInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Providence", &s_providenceInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Create Structure")) {
        std::string blessedId = BlessedDominion::BlessedDominionEngine::CreateBlessedDominionStructure(s_nameBuffer);
        BlessedDominion::BlessedDominionEngine::ElevateBlessedness(blessedId, s_blessednessInput);
        BlessedDominion::BlessedDominionEngine::ExpandDominion(blessedId, s_dominionInput);
        BlessedDominion::BlessedDominionEngine::BestowGrace(blessedId, s_graceInput);
        BlessedDominion::BlessedDominionEngine::GrantFavor(blessedId, s_favorInput);
        BlessedDominion::BlessedDominionEngine::ProvideProvidence(blessedId, s_providenceInput);
        OnBlessedStructureCreated(blessedId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Created Structures:");
    auto structures = BlessedDominion::BlessedDominionEngine::GetAllBlessedDominionStructures();
    for (const auto& structure : structures) {
        ImGui::PushID(structure.blessedId.c_str());
        if (ImGui::Selectable(structure.name.c_str(), s_selectedBlessedId == structure.blessedId)) {
            s_selectedBlessedId = structure.blessedId;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("ID: %s\nBlessedness: %.2f\nDominion: %.2f\nGrace: %.2f\nFavor: %.2f\nProvidence: %.2f",
                structure.blessedId.c_str(), structure.blessedness, structure.dominion, 
                structure.grace, structure.favor, structure.providence);
        }
        ImGui::PopID();
    }
}

void BlessedDominionPanel::RenderDominionBlessedTab() {
    ImGui::Text("Dominion Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Dominion", &s_dominionBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessDominionInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Authority", &s_authorityInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Sovereignty", &s_sovereigntyInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Establish Dominion")) {
        std::string dominionId = BlessedDominion::BlessedDominionEngine::CreateDominionBlessed(s_nameBuffer);
        BlessedDominion::BlessedDominionEngine::AssertAuthority(dominionId, s_authorityInput);
        BlessedDominion::BlessedDominionEngine::ClaimSovereignty(dominionId, s_sovereigntyInput);
        OnDominionEstablished(dominionId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Dominions:");
    auto dominions = BlessedDominion::BlessedDominionEngine::GetAllDominionBlesseds();
    for (const auto& dominion : dominions) {
        ImGui::PushID(dominion.dominionId.c_str());
        bool isSelected = s_selectedDominionId == dominion.dominionId;
        if (ImGui::Selectable(dominion.name.c_str(), isSelected)) {
            s_selectedDominionId = dominion.dominionId;
        }
        ImGui::SameLine();
        if (dominion.isSovereign) {
            ImGui::TextColored(ImVec4(0.5f, 1, 0.8f, 1), "[SOVEREIGN]");
        } else {
            ImGui::TextColored(ImVec4(0.5, 0.5, 0.5, 1), "[SUBJECT]");
        }
        if (s_selectedDominionId == dominion.dominionId) {
            if (!dominion.isSovereign && ImGui::Button("Declare Sovereign")) {
                BlessedDominion::BlessedDominionEngine::DeclareSovereign(dominion.dominionId);
            }
        }
        ImGui::PopID();
    }
}

void BlessedDominionPanel::RenderGraceBlessedTab() {
    ImGui::Text("Grace Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Grace", &s_graceBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessGraceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Mercy", &s_mercyInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Kindness", &s_kindnessInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Bestow Grace")) {
        std::string graceId = BlessedDominion::BlessedDominionEngine::CreateGraceBlessed(s_nameBuffer);
        BlessedDominion::BlessedDominionEngine::ExtendMercy(graceId, s_mercyInput);
        BlessedDominion::BlessedDominionEngine::ShowKindness(graceId, s_kindnessInput);
        OnGraceBestowed(graceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Bestowed Graces:");
    auto graces = BlessedDominion::BlessedDominionEngine::GetAllGraceBlesseds();
    for (const auto& grace : graces) {
        ImGui::PushID(grace.graceId.c_str());
        if (ImGui::Selectable(grace.name.c_str(), s_selectedGraceId == grace.graceId)) {
            s_selectedGraceId = grace.graceId;
        }
        if (s_selectedGraceId == grace.graceId) {
            ImGui::Text("Grace: %.2f | Blessedness: %.2f | Mercy: %.2f | Kindness: %.2f",
                grace.grace, grace.blessedness, grace.mercy, grace.kindness);
        }
        ImGui::PopID();
    }
}

void BlessedDominionPanel::RenderFavorBlessedTab() {
    ImGui::Text("Favor Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Favor", &s_favorBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessFavorInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Preference", &s_preferenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Approval", &s_approvalInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Grant Favor")) {
        std::string favorId = BlessedDominion::BlessedDominionEngine::CreateFavorBlessed(s_nameBuffer);
        BlessedDominion::BlessedDominionEngine::ExpressPreference(favorId, s_preferenceInput);
        BlessedDominion::BlessedDominionEngine::GrantApproval(favorId, s_approvalInput);
        OnFavorGranted(favorId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Granted Favors:");
    auto favors = BlessedDominion::BlessedDominionEngine::GetAllFavorBlesseds();
    for (const auto& favor : favors) {
        ImGui::PushID(favor.favorId.c_str());
        bool isSelected = s_selectedFavorId == favor.favorId;
        if (ImGui::Selectable(favor.name.c_str(), isSelected)) {
            s_selectedFavorId = favor.favorId;
        }
        ImGui::SameLine();
        if (favor.isPreferred) {
            ImGui::TextColored(ImVec4(1, 0.8f, 0.2f, 1), "[PREFERRED]");
        }
        if (s_selectedFavorId == favor.favorId) {
            ImGui::Text("Favor: %.2f | Blessedness: %.2f | Preference: %.2f | Approval: %.2f",
                favor.favor, favor.blessedness, favor.preference, favor.approval);
            if (!favor.isPreferred && ImGui::Button("Declare Preferred")) {
                BlessedDominion::BlessedDominionEngine::DeclarePreferred(favor.favorId);
            }
        }
        ImGui::PopID();
    }
}

void BlessedDominionPanel::RenderProvidenceBlessedTab() {
    ImGui::Text("Providence Blessed Management");
    ImGui::Separator();
    
    ImGui::InputText("Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::SliderFloat("Providence", &s_providenceBlessedInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Blessedness", &s_blessednessProvidenceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Guidance", &s_guidanceInput, 0.0f, 1.0f);
    ImGui::SliderFloat("Protection", &s_protectionInput, 0.0f, 1.0f);
    
    if (ImGui::Button("Provide Providence")) {
        std::string providenceId = BlessedDominion::BlessedDominionEngine::CreateProvidenceBlessed(s_nameBuffer);
        BlessedDominion::BlessedDominionEngine::OfferGuidance(providenceId, s_guidanceInput);
        BlessedDominion::BlessedDominionEngine::ExtendProtection(providenceId, s_protectionInput);
        OnProvidenceProvided(providenceId);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Provided Providences:");
    auto providences = BlessedDominion::BlessedDominionEngine::GetAllProvidenceBlesseds();
    for (const auto& providence : providences) {
        ImGui::PushID(providence.providenceId.c_str());
        if (ImGui::Selectable(providence.name.c_str(), s_selectedProvidenceId == providence.providenceId)) {
            s_selectedProvidenceId = providence.providenceId;
        }
        if (s_selectedProvidenceId == providence.providenceId) {
            ImGui::Text("Providence: %.2f | Blessedness: %.2f | Guidance: %.2f | Protection: %.2f",
                providence.providence, providence.blessedness, providence.guidance, providence.protection);
        }
        ImGui::PopID();
    }
}

void BlessedDominionPanel::RenderBlessedMetricsTab() {
    ImGui::Text("Blessed Dominion Metrics");
    ImGui::Separator();
    
    auto metrics = BlessedDominion::BlessedDominionEngine::GetBlessedDominionMetrics();
    
    ImGui::Text("Blessed Count: %d", metrics["blessedCount"].get<int>());
    ImGui::Text("Dominion Count: %d", metrics["dominionCount"].get<int>());
    ImGui::Text("Grace Count: %d", metrics["graceCount"].get<int>());
    ImGui::Text("Favor Count: %d", metrics["favorCount"].get<int>());
    ImGui::Text("Providence Count: %d", metrics["providenceCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Blessedness: %.4f", metrics["totalBlessedness"].get<float>());
    ImGui::Text("Average Blessedness: %.4f", metrics["averageBlessedness"].get<float>());
    ImGui::Text("Blessed Blesseds: %d", metrics["blessedBlesseds"].get<int>());
    ImGui::Text("Total Dominion: %.4f", metrics["totalDominion"].get<float>());
    ImGui::Text("Sovereign Dominions: %d", metrics["sovereignDominions"].get<int>());
    ImGui::Text("Preferred Favors: %d", metrics["preferredFavors"].get<int>());
    ImGui::Separator();
    ImGui::Text("Tick Count: %lld", BlessedDominion::BlessedDominionLoop::GetTickCount());
    ImGui::Text("Loop FPS: %.1f", BlessedDominion::BlessedDominionLoop::GetCurrentFPS());
    
    if (ImGui::Button("Export Blessed Report")) {
        auto report = BlessedDominion::BlessedDominionEngine::GenerateBlessedDominionReport();
        // Export logic would go here
    }
}

void BlessedDominionPanel::RenderBlessedVisualizationTab() {
    ImGui::Text("Blessed Dominion Visualization");
    ImGui::Separator();
    
    // Draw a representation of blessed dominion
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImVec2 canvas_size = ImVec2(ImGui::GetContentRegionAvail().x, 300);
    
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    draw_list->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y + canvas_size.y), IM_COL32(20, 25, 40, 255));
    
    // Draw blessed structures as golden orbs
    auto structures = BlessedDominion::BlessedDominionEngine::GetAllBlessedDominionStructures();
    float centerX = canvas_pos.x + canvas_size.x / 2;
    float centerY = canvas_pos.y + canvas_size.y / 2;
    
    int idx = 0;
    for (const auto& structure : structures) {
        float angle = (idx * 2.0f * 3.14159f) / std::max(1, (int)structures.size());
        float radius = 60.0f + structure.blessedness * 70.0f;
        float x = centerX + std::cos(angle) * radius;
        float y = centerY + std::sin(angle) * radius;
        float size = 6.0f + structure.grace * 10.0f;
        
        // Blessed glow effect (golden)
        for (int i = 6; i > 0; i--) {
            draw_list->AddCircleFilled(ImVec2(x, y), size + i * 6, IM_COL32(255, 215, 100, 35 - i * 5), 16);
        }
        // Core orb
        draw_list->AddCircleFilled(ImVec2(x, y), size, IM_COL32(255, 230, 150, 255), 16);
        
        // Label
        draw_list->AddText(ImVec2(x - 25, y + size + 5), IM_COL32(255, 255, 255, 255), structure.name.c_str());
        idx++;
    }
    
    // Draw dominion blesseds as authority rays
    auto dominions = BlessedDominion::BlessedDominionEngine::GetAllDominionBlesseds();
    int dominionIdx = 0;
    for (const auto& dominion : dominions) {
        float angle = (dominionIdx * 2.0f * 3.14159f) / std::max(1, (int)dominions.size()) + ImGui::GetTime() * 0.3f;
        float innerRadius = 25.0f;
        float outerRadius = 90.0f + dominion.authority * 50.0f;
        
        float x1 = centerX + std::cos(angle) * innerRadius;
        float y1 = centerY + std::sin(angle) * innerRadius;
        float x2 = centerX + std::cos(angle) * outerRadius;
        float y2 = centerY + std::sin(angle) * outerRadius;
        
        ImU32 color = dominion.isSovereign ? 
            IM_COL32(255, 200, 100, 180) : IM_COL32(150, 150, 150, 100);
        draw_list->AddLine(ImVec2(x1, y1), ImVec2(x2, y2), color, 2.0f + dominion.dominion * 3.0f);
        dominionIdx++;
    }
    
    ImGui::Dummy(canvas_size);
    
    // Event log
    ImGui::Separator();
    ImGui::Text("Blessed Event Log:");
    ImGui::BeginChild("BlessedEvents", ImVec2(0, 150), true);
    for (auto it = s_blessedEvents.rbegin(); it != s_blessedEvents.rend(); ++it) {
        ImGui::Text("[%s] %s", 
            it->value("type", "unknown").c_str(),
            it->value("timestamp", 0) > 0 ? "Event" : "Unknown");
    }
    ImGui::EndChild();
}

} // namespace IDE
