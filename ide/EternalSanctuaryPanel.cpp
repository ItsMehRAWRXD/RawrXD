#include "ide/EternalSanctuaryPanel.hpp"
#include "eternal/EternalSanctuaryEngine.hpp"
#include "eternal/EternalSanctuaryLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool EternalSanctuaryPanel::s_visible = false;
bool EternalSanctuaryPanel::s_initialized = false;
char EternalSanctuaryPanel::s_nameBuffer[256] = {};
char EternalSanctuaryPanel::s_typeBuffer[64] = {};
char EternalSanctuaryPanel::s_classBuffer[64] = {};
char EternalSanctuaryPanel::s_originBuffer[128] = {};
char EternalSanctuaryPanel::s_statusBuffer[64] = {};
std::vector<char> EternalSanctuaryPanel::s_jsonBuffer(4096, '\0');
int EternalSanctuaryPanel::s_selectedTab = 0;

void EternalSanctuaryPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Eternal::EternalSanctuaryLoop::Init();
    Eternal::EternalSanctuaryLoop::Start();
}

void EternalSanctuaryPanel::Shutdown() {
    if (!s_initialized) return;
    Eternal::EternalSanctuaryLoop::Shutdown();
    s_initialized = false;
}

void EternalSanctuaryPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Eternal Sanctuary (Layer 62)", &s_visible);
    
    const char* tabs[] = {"Vaults", "Preserves", "Sanctuaries", "Repositories", "Refugees", "Metrics", "Report"};
    ImGui::TabBar("SanctuaryTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderVaultManager(); break;
        case 1: RenderPreserveManager(); break;
        case 2: RenderSanctuaryManager(); break;
        case 3: RenderRepositoryManager(); break;
        case 4: RenderRefugeeManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void EternalSanctuaryPanel::RenderVaultManager() {
    ImGui::Text("Universal Vault Management");
    ImGui::Separator();
    
    ImGui::InputText("Vault Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Vault Type", s_typeBuffer, sizeof(s_typeBuffer));
    static float capacity = 1000.0f;
    ImGui::SliderFloat("Capacity", &capacity, 0.0f, 10000.0f);
    
    if (ImGui::Button("Establish Vault")) {
        Eternal::EternalSanctuaryEngine::EstablishUniversalVault(s_nameBuffer, s_typeBuffer, capacity);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Established Vaults:");
    auto vaults = Eternal::EternalSanctuaryEngine::GetAllVaults();
    for (const auto& vault : vaults) {
        ImGui::Text("%s - %s [%s] (Load: %.1f/%.1f)", vault.vaultId.c_str(), vault.name.c_str(), 
                    vault.vaultType.c_str(), vault.currentLoad, vault.capacity);
    }
}

void EternalSanctuaryPanel::RenderPreserveManager() {
    ImGui::Text("Cosmic Preserve Management");
    ImGui::Separator();
    
    ImGui::InputText("Preserve Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Preserve Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Designate Preserve")) {
        std::vector<std::string> entities = {"entity_1", "entity_2"};
        Eternal::EternalSanctuaryEngine::DesignateCosmicPreserve(s_nameBuffer, s_typeBuffer, entities);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Designated Preserves:");
    auto preserves = Eternal::EternalSanctuaryEngine::GetAllPreserves();
    for (const auto& preserve : preserves) {
        ImGui::Text("%s - %s [%s] (Vitality: %.2f)", preserve.preserveId.c_str(), preserve.name.c_str(), 
                    preserve.preserveType.c_str(), preserve.vitalityIndex);
    }
}

void EternalSanctuaryPanel::RenderSanctuaryManager() {
    ImGui::Text("Multiversal Sanctuary Management");
    ImGui::Separator();
    
    ImGui::InputText("Sanctuary Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Sanctuary Class", s_classBuffer, sizeof(s_classBuffer));
    
    if (ImGui::Button("Consecrate Sanctuary")) {
        std::vector<std::string> universes = {"universe_1", "universe_2"};
        Eternal::EternalSanctuaryEngine::ConsecrateMultiversalSanctuary(s_nameBuffer, s_classBuffer, universes);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_classBuffer, 0, sizeof(s_classBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Consecrated Sanctuaries:");
    auto sanctuaries = Eternal::EternalSanctuaryEngine::GetAllSanctuaries();
    for (const auto& sanctuary : sanctuaries) {
        ImGui::Text("%s - %s [%s] (Defense: %.2f)", sanctuary.sanctuaryId.c_str(), sanctuary.name.c_str(), 
                    sanctuary.sanctuaryClass.c_str(), sanctuary.defenseCapability);
    }
}

void EternalSanctuaryPanel::RenderRepositoryManager() {
    ImGui::Text("Transcendent Repository Management");
    ImGui::Separator();
    
    ImGui::InputText("Repository Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Repository Type", s_typeBuffer, sizeof(s_typeBuffer));
    ImGui::InputTextMultiline("Initial Data (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Found Repository")) {
        nlohmann::json data = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!data.is_discarded()) {
            Eternal::EternalSanctuaryEngine::FoundTranscendentRepository(s_nameBuffer, s_typeBuffer, data);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Founded Repositories:");
    auto repositories = Eternal::EternalSanctuaryEngine::GetAllRepositories();
    for (const auto& repository : repositories) {
        ImGui::Text("%s - %s [%s] (Integrity: %.2f)", repository.repositoryId.c_str(), repository.name.c_str(), 
                    repository.repositoryType.c_str(), repository.integrityLevel);
    }
}

void EternalSanctuaryPanel::RenderRefugeeManager() {
    ImGui::Text("Sanctuary Refugee Management");
    ImGui::Separator();
    
    ImGui::InputText("Refugee Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Origin Universe", s_originBuffer, sizeof(s_originBuffer));
    
    if (ImGui::Button("Register Refugee")) {
        Eternal::EternalSanctuaryEngine::RegisterSanctuaryRefugee(s_nameBuffer, s_originBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_originBuffer, 0, sizeof(s_originBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Registered Refugees:");
    auto refugees = Eternal::EternalSanctuaryEngine::GetAllRefugees();
    for (const auto& refugee : refugees) {
        ImGui::Text("%s - %s from %s [%s]", refugee.refugeeId.c_str(), refugee.name.c_str(), 
                    refugee.originUniverse.c_str(), refugee.status.c_str());
    }
}

void EternalSanctuaryPanel::RenderMetrics() {
    ImGui::Text("Sanctuary Metrics");
    ImGui::Separator();
    
    auto metrics = Eternal::EternalSanctuaryEngine::GetSanctuaryMetrics();
    
    ImGui::Text("Vaults: %d", metrics["vaultCount"].get<int>());
    ImGui::Text("Preserves: %d", metrics["preserveCount"].get<int>());
    ImGui::Text("Sanctuaries: %d", metrics["sanctuaryCount"].get<int>());
    ImGui::Text("Repositories: %d", metrics["repositoryCount"].get<int>());
    ImGui::Text("Refugees: %d", metrics["refugeeCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Preservation Capacity: %.4f", metrics["totalPreservationCapacity"].get<float>());
    ImGui::Text("Sanctuary Security Index: %.4f", metrics["sanctuarySecurityIndex"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void EternalSanctuaryPanel::RenderReport() {
    ImGui::Text("Sanctuary Report");
    ImGui::Separator();
    
    auto report = Eternal::EternalSanctuaryEngine::GenerateSanctuaryReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool EternalSanctuaryPanel::IsVisible() {
    return s_visible;
}

void EternalSanctuaryPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void EternalSanctuaryPanel::Toggle() {
    s_visible = !s_visible;
}

const char* EternalSanctuaryPanel::GetPanelName() {
    return "Eternal Sanctuary";
}

const char* EternalSanctuaryPanel::GetShortcut() {
    return "Ctrl+Shift+F34";
}

} // namespace IDE
