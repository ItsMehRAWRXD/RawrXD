#include "ide/UniversalCouncilPanel.hpp"
#include "universal/UniversalCouncilEngine.hpp"
#include "universal/UniversalCouncilLoop.hpp"
#include <imgui.h>
#include <string>

namespace IDE {

bool UniversalCouncilPanel::s_visible = false;
bool UniversalCouncilPanel::s_initialized = false;
char UniversalCouncilPanel::s_nameBuffer[256] = {};
char UniversalCouncilPanel::s_descriptionBuffer[512] = {};
char UniversalCouncilPanel::s_scopeBuffer[128] = {};
char UniversalCouncilPanel::s_assemblyTypeBuffer[128] = {};
std::vector<char> UniversalCouncilPanel::s_jsonBuffer(4096, '\0');
int UniversalCouncilPanel::s_selectedTab = 0;

void UniversalCouncilPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Universal::UniversalCouncilLoop::Init();
    Universal::UniversalCouncilLoop::Start();
}

void UniversalCouncilPanel::Shutdown() {
    if (!s_initialized) return;
    Universal::UniversalCouncilLoop::Shutdown();
    s_initialized = false;
}

void UniversalCouncilPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Universal Council (Layer 56)", &s_visible);
    
    const char* tabs[] = {"Domains", "Mandates", "Coalitions", "Directives", "Assemblies", "Metrics", "Report"};
    ImGui::TabBar("UniversalTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderDomainManager(); break;
        case 1: RenderMandateManager(); break;
        case 2: RenderCoalitionManager(); break;
        case 3: RenderDirectiveManager(); break;
        case 4: RenderAssemblyManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void UniversalCouncilPanel::RenderDomainManager() {
    ImGui::Text("Universal Domain Management");
    ImGui::Separator();
    
    ImGui::InputText("Domain Name", s_nameBuffer, sizeof(s_nameBuffer));
    
    static float extent[3] = {1000.0f, 1000.0f, 1000.0f};
    ImGui::InputFloat3("Cosmic Extent", extent);
    
    if (ImGui::Button("Form Domain")) {
        std::vector<std::string> regions = {"region_1", "region_2"};
        Universal::UniversalCouncilEngine::FormUniversalDomain(s_nameBuffer, regions, extent);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Domains:");
    auto domains = Universal::UniversalCouncilEngine::GetAllUniversalDomains();
    for (const auto& domain : domains) {
        ImGui::Text("%s - %s (Unity: %.2f)", domain.domainId.c_str(), domain.name.c_str(), domain.unityIndex);
    }
}

void UniversalCouncilPanel::RenderMandateManager() {
    ImGui::Text("Universal Mandate Management");
    ImGui::Separator();
    
    ImGui::InputText("Mandate Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Description", s_descriptionBuffer, sizeof(s_descriptionBuffer));
    
    if (ImGui::Button("Issue Mandate")) {
        std::map<std::string, nlohmann::json> provisions;
        provisions["scope"] = "universal";
        provisions["priority"] = "high";
        Universal::UniversalCouncilEngine::IssueUniversalMandate(s_nameBuffer, s_descriptionBuffer, provisions);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_descriptionBuffer, 0, sizeof(s_descriptionBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Mandates:");
    auto mandates = Universal::UniversalCouncilEngine::GetAllMandates();
    for (const auto& mandate : mandates) {
        ImGui::Text("%s - %s [%s]", mandate.mandateId.c_str(), mandate.name.c_str(), 
                    mandate.active ? "ACTIVE" : "INACTIVE");
    }
}

void UniversalCouncilPanel::RenderCoalitionManager() {
    ImGui::Text("Cosmic Coalition Management");
    ImGui::Separator();
    
    ImGui::InputText("Coalition Name", s_nameBuffer, sizeof(s_nameBuffer));
    
    if (ImGui::Button("Form Coalition")) {
        std::vector<std::string> domains = {"domain_1", "domain_2"};
        Universal::UniversalCouncilEngine::FormCosmicCoalition(s_nameBuffer, domains);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Coalitions:");
    auto coalitions = Universal::UniversalCouncilEngine::GetAllCoalitions();
    for (const auto& coalition : coalitions) {
        float strength = Universal::UniversalCouncilEngine::CalculateCoalitionStrength(coalition.coalitionId);
        ImGui::Text("%s - %s (Strength: %.2f)", coalition.coalitionId.c_str(), coalition.name.c_str(), strength);
    }
}

void UniversalCouncilPanel::RenderDirectiveManager() {
    ImGui::Text("Omniversal Directive Management");
    ImGui::Separator();
    
    ImGui::InputText("Directive Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Scope", s_scopeBuffer, sizeof(s_scopeBuffer));
    ImGui::InputTextMultiline("Directive Data (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Issue Directive")) {
        nlohmann::json data = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!data.is_discarded()) {
            Universal::UniversalCouncilEngine::IssueOmniversalDirective(s_nameBuffer, s_scopeBuffer, data);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_scopeBuffer, 0, sizeof(s_scopeBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Active Directives:");
    auto directives = Universal::UniversalCouncilEngine::GetAllDirectives();
    for (const auto& directive : directives) {
        ImGui::Text("%s - %s [%s]", directive.directiveId.c_str(), directive.name.c_str(), directive.scope.c_str());
    }
}

void UniversalCouncilPanel::RenderAssemblyManager() {
    ImGui::Text("Universal Assembly Management");
    ImGui::Separator();
    
    ImGui::InputText("Assembly Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Assembly Type", s_assemblyTypeBuffer, sizeof(s_assemblyTypeBuffer));
    
    if (ImGui::Button("Convene Assembly")) {
        std::vector<std::string> domains = {"domain_1", "domain_2", "domain_3"};
        Universal::UniversalCouncilEngine::ConveneUniversalAssembly(s_nameBuffer, s_assemblyTypeBuffer, domains);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_assemblyTypeBuffer, 0, sizeof(s_assemblyTypeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Assemblies:");
    auto assemblies = Universal::UniversalCouncilEngine::GetAllAssemblies();
    for (const auto& assembly : assemblies) {
        ImGui::Text("%s - %s [%s]", assembly.assemblyId.c_str(), assembly.name.c_str(), assembly.assemblyType.c_str());
    }
}

void UniversalCouncilPanel::RenderMetrics() {
    ImGui::Text("Universal Metrics");
    ImGui::Separator();
    
    auto metrics = Universal::UniversalCouncilEngine::GetUniversalMetrics();
    
    ImGui::Text("Domains: %d", metrics["domainCount"].get<int>());
    ImGui::Text("Mandates: %d", metrics["mandateCount"].get<int>());
    ImGui::Text("Coalitions: %d", metrics["coalitionCount"].get<int>());
    ImGui::Text("Directives: %d", metrics["directiveCount"].get<int>());
    ImGui::Text("Assemblies: %d", metrics["assemblyCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Universal Unity: %.4f", metrics["universalUnity"].get<float>());
    ImGui::Text("Cosmic Harmony: %.4f", metrics["cosmicHarmony"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void UniversalCouncilPanel::RenderReport() {
    ImGui::Text("Universal Report");
    ImGui::Separator();
    
    auto report = Universal::UniversalCouncilEngine::GenerateUniversalReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool UniversalCouncilPanel::IsVisible() {
    return s_visible;
}

void UniversalCouncilPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void UniversalCouncilPanel::Toggle() {
    s_visible = !s_visible;
}

const char* UniversalCouncilPanel::GetPanelName() {
    return "Universal Council";
}

const char* UniversalCouncilPanel::GetShortcut() {
    return "Ctrl+Shift+F28";
}

} // namespace IDE
