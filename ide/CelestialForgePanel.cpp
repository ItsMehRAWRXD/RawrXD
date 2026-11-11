#include "ide/CelestialForgePanel.hpp"
#include "celestial/CelestialForgeEngine.hpp"
#include "celestial/CelestialForgeLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool CelestialForgePanel::s_visible = false;
bool CelestialForgePanel::s_initialized = false;
char CelestialForgePanel::s_nameBuffer[256] = {};
char CelestialForgePanel::s_typeBuffer[64] = {};
char CelestialForgePanel::s_methodBuffer[64] = {};
char CelestialForgePanel::s_domainBuffer[64] = {};
char CelestialForgePanel::s_creatorBuffer[128] = {};
std::vector<char> CelestialForgePanel::s_jsonBuffer(4096, '\0');
int CelestialForgePanel::s_selectedTab = 0;

void CelestialForgePanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Celestial::CelestialForgeLoop::Init();
    Celestial::CelestialForgeLoop::Start();
}

void CelestialForgePanel::Shutdown() {
    if (!s_initialized) return;
    Celestial::CelestialForgeLoop::Shutdown();
    s_initialized = false;
}

void CelestialForgePanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Celestial Forge (Layer 60)", &s_visible);
    
    const char* tabs[] = {"Constructors", "Fabricators", "Synthesizers", "Creation Engines", "Artifacts", "Metrics", "Report"};
    ImGui::TabBar("ForgeTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderConstructorManager(); break;
        case 1: RenderFabricatorManager(); break;
        case 2: RenderSynthesizerManager(); break;
        case 3: RenderCreationEngineManager(); break;
        case 4: RenderArtifactManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void CelestialForgePanel::RenderConstructorManager() {
    ImGui::Text("Universal Constructor Management");
    ImGui::Separator();
    
    ImGui::InputText("Constructor Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Construction Type", s_typeBuffer, sizeof(s_typeBuffer));
    static float capacity = 100.0f;
    ImGui::SliderFloat("Output Capacity", &capacity, 0.0f, 1000.0f);
    
    if (ImGui::Button("Commission Constructor")) {
        Celestial::CelestialForgeEngine::CommissionUniversalConstructor(s_nameBuffer, s_typeBuffer, capacity);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Constructors:");
    auto constructors = Celestial::CelestialForgeEngine::GetAllConstructors();
    for (const auto& constructor : constructors) {
        ImGui::Text("%s - %s [%s] (Cap: %.2f)", constructor.constructorId.c_str(), constructor.name.c_str(), 
                    constructor.active ? "ACTIVE" : "INACTIVE", constructor.outputCapacity);
    }
}

void CelestialForgePanel::RenderFabricatorManager() {
    ImGui::Text("Cosmic Fabricator Management");
    ImGui::Separator();
    
    ImGui::InputText("Fabricator Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Fabrication Method", s_methodBuffer, sizeof(s_methodBuffer));
    
    if (ImGui::Button("Deploy Fabricator")) {
        Celestial::CelestialForgeEngine::DeployCosmicFabricator(s_nameBuffer, s_methodBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_methodBuffer, 0, sizeof(s_methodBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Deployed Fabricators:");
    auto fabricators = Celestial::CelestialForgeEngine::GetAllFabricators();
    for (const auto& fabricator : fabricators) {
        ImGui::Text("%s - %s [%s] (Rate: %.2f)", fabricator.fabricatorId.c_str(), fabricator.name.c_str(), 
                    fabricator.fabricationMethod.c_str(), fabricator.productionRate);
    }
}

void CelestialForgePanel::RenderSynthesizerManager() {
    ImGui::Text("Multiversal Synthesizer Management");
    ImGui::Separator();
    
    ImGui::InputText("Synthesizer Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Synthesis Type", s_typeBuffer, sizeof(s_typeBuffer));
    ImGui::InputTextMultiline("Formula (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Establish Synthesizer")) {
        nlohmann::json formula = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!formula.is_discarded()) {
            Celestial::CelestialForgeEngine::EstablishMultiversalSynthesizer(s_nameBuffer, s_typeBuffer, formula);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Active Synthesizers:");
    auto synthesizers = Celestial::CelestialForgeEngine::GetAllSynthesizers();
    for (const auto& synthesizer : synthesizers) {
        ImGui::Text("%s - %s [%s] (Purity: %.2f)", synthesizer.synthesizerId.c_str(), synthesizer.name.c_str(), 
                    synthesizer.synthesisType.c_str(), synthesizer.purityLevel);
    }
}

void CelestialForgePanel::RenderCreationEngineManager() {
    ImGui::Text("Transcendent Creation Engine Management");
    ImGui::Separator();
    
    ImGui::InputText("Engine Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Creation Domain", s_domainBuffer, sizeof(s_domainBuffer));
    static float power = 100.0f;
    ImGui::SliderFloat("Creation Power", &power, 0.0f, 1000.0f);
    
    if (ImGui::Button("Activate Engine")) {
        Celestial::CelestialForgeEngine::ActivateCreationEngine(s_nameBuffer, s_domainBuffer, power);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_domainBuffer, 0, sizeof(s_domainBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Creation Engines:");
    auto engines = Celestial::CelestialForgeEngine::GetAllCreationEngines();
    for (const auto& engine : engines) {
        ImGui::Text("%s - %s [%s] (Power: %.2f)", engine.engineId.c_str(), engine.name.c_str(), 
                    engine.creationDomain.c_str(), engine.creationPower);
    }
}

void CelestialForgePanel::RenderArtifactManager() {
    ImGui::Text("Celestial Artifact Management");
    ImGui::Separator();
    
    ImGui::InputText("Artifact Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Artifact Type", s_typeBuffer, sizeof(s_typeBuffer));
    ImGui::InputText("Creator ID", s_creatorBuffer, sizeof(s_creatorBuffer));
    ImGui::InputTextMultiline("Properties (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Forge Artifact")) {
        nlohmann::json properties = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!properties.is_discarded()) {
            Celestial::CelestialForgeEngine::ForgeCelestialArtifact(s_nameBuffer, s_typeBuffer, s_creatorBuffer, properties);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
            memset(s_creatorBuffer, 0, sizeof(s_creatorBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Forged Artifacts:");
    auto artifacts = Celestial::CelestialForgeEngine::GetAllArtifacts();
    for (const auto& artifact : artifacts) {
        ImGui::Text("%s - %s [%s] (Power: %.2f)", artifact.artifactId.c_str(), artifact.name.c_str(), 
                    artifact.artifactType.c_str(), artifact.powerLevel);
    }
}

void CelestialForgePanel::RenderMetrics() {
    ImGui::Text("Forge Metrics");
    ImGui::Separator();
    
    auto metrics = Celestial::CelestialForgeEngine::GetForgeMetrics();
    
    ImGui::Text("Constructors: %d (%d active)", metrics["constructorCount"].get<int>(), metrics["activeConstructorCount"].get<int>());
    ImGui::Text("Fabricators: %d", metrics["fabricatorCount"].get<int>());
    ImGui::Text("Synthesizers: %d", metrics["synthesizerCount"].get<int>());
    ImGui::Text("Creation Engines: %d", metrics["creationEngineCount"].get<int>());
    ImGui::Text("Artifacts: %d", metrics["artifactCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Production Capacity: %.4f", metrics["totalProductionCapacity"].get<float>());
    ImGui::Text("Forge Efficiency: %.4f", metrics["forgeEfficiency"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void CelestialForgePanel::RenderReport() {
    ImGui::Text("Forge Report");
    ImGui::Separator();
    
    auto report = Celestial::CelestialForgeEngine::GenerateForgeReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool CelestialForgePanel::IsVisible() {
    return s_visible;
}

void CelestialForgePanel::SetVisible(bool visible) {
    s_visible = visible;
}

void CelestialForgePanel::Toggle() {
    s_visible = !s_visible;
}

const char* CelestialForgePanel::GetPanelName() {
    return "Celestial Forge";
}

const char* CelestialForgePanel::GetShortcut() {
    return "Ctrl+Shift+F32";
}

} // namespace IDE
