#include "ide/OmniversalTribunalPanel.hpp"
#include "omniversal/OmniversalTribunalEngine.hpp"
#include "omniversal/OmniversalTribunalLoop.hpp"
#include <imgui.h>
#include <string>

namespace IDE {

bool OmniversalTribunalPanel::s_visible = false;
bool OmniversalTribunalPanel::s_initialized = false;
char OmniversalTribunalPanel::s_nameBuffer[256] = {};
char OmniversalTribunalPanel::s_descriptionBuffer[512] = {};
char OmniversalTribunalPanel::s_jurisdictionBuffer[128] = {};
char OmniversalTribunalPanel::s_scopeBuffer[128] = {};
char OmniversalTribunalPanel::s_specializationBuffer[128] = {};
char OmniversalTribunalPanel::s_statusBuffer[64] = {};
char OmniversalTribunalPanel::s_rulingBuffer[64] = {};
std::vector<char> OmniversalTribunalPanel::s_jsonBuffer(4096, '\0');
int OmniversalTribunalPanel::s_selectedTab = 0;

void OmniversalTribunalPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Omniversal::OmniversalTribunalLoop::Init();
    Omniversal::OmniversalTribunalLoop::Start();
}

void OmniversalTribunalPanel::Shutdown() {
    if (!s_initialized) return;
    Omniversal::OmniversalTribunalLoop::Shutdown();
    s_initialized = false;
}

void OmniversalTribunalPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Omniversal Tribunal (Layer 57)", &s_visible);
    
    const char* tabs[] = {"Courts", "Cases", "Laws", "Arbitrators", "Verdicts", "Metrics", "Report"};
    ImGui::TabBar("TribunalTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderCourtManager(); break;
        case 1: RenderCaseManager(); break;
        case 2: RenderLawManager(); break;
        case 3: RenderArbitratorManager(); break;
        case 4: RenderVerdictManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void OmniversalTribunalPanel::RenderCourtManager() {
    ImGui::Text("Omniversal Court Management");
    ImGui::Separator();
    
    ImGui::InputText("Court Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Jurisdiction", s_jurisdictionBuffer, sizeof(s_jurisdictionBuffer));
    
    if (ImGui::Button("Establish Court")) {
        std::vector<std::string> universes = {"universe_1", "universe_2"};
        Omniversal::OmniversalTribunalEngine::EstablishOmniversalCourt(s_nameBuffer, s_jurisdictionBuffer, universes);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_jurisdictionBuffer, 0, sizeof(s_jurisdictionBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Courts:");
    auto courts = Omniversal::OmniversalTribunalEngine::GetAllCourts();
    for (const auto& court : courts) {
        ImGui::Text("%s - %s [%s] (Authority: %.2f)", court.courtId.c_str(), court.name.c_str(), 
                    court.jurisdiction.c_str(), court.authorityLevel);
    }
}

void OmniversalTribunalPanel::RenderCaseManager() {
    ImGui::Text("Cosmic Justice Case Management");
    ImGui::Separator();
    
    ImGui::InputText("Case Title", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Description", s_descriptionBuffer, sizeof(s_descriptionBuffer));
    static char plaintiffBuffer[128] = {};
    static char defendantBuffer[128] = {};
    ImGui::InputText("Plaintiff", plaintiffBuffer, sizeof(plaintiffBuffer));
    ImGui::InputText("Defendant", defendantBuffer, sizeof(defendantBuffer));
    
    if (ImGui::Button("File Case")) {
        Omniversal::OmniversalTribunalEngine::FileCosmicJusticeCase(s_nameBuffer, s_descriptionBuffer, plaintiffBuffer, defendantBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_descriptionBuffer, 0, sizeof(s_descriptionBuffer));
        memset(plaintiffBuffer, 0, sizeof(plaintiffBuffer));
        memset(defendantBuffer, 0, sizeof(defendantBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Active Cases:");
    auto cases = Omniversal::OmniversalTribunalEngine::GetAllCases();
    for (const auto& caseData : cases) {
        ImGui::Text("%s - %s [%s]", caseData.caseId.c_str(), caseData.title.c_str(), caseData.status.c_str());
    }
}

void OmniversalTribunalPanel::RenderLawManager() {
    ImGui::Text("Multiversal Law Management");
    ImGui::Separator();
    
    ImGui::InputText("Law Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputTextMultiline("Description", s_descriptionBuffer, sizeof(s_descriptionBuffer));
    ImGui::InputText("Scope", s_scopeBuffer, sizeof(s_scopeBuffer));
    ImGui::InputTextMultiline("Provisions (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Enact Law")) {
        nlohmann::json provisions = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!provisions.is_discarded()) {
            Omniversal::OmniversalTribunalEngine::EnactMultiversalLaw(s_nameBuffer, s_descriptionBuffer, s_scopeBuffer, provisions);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_descriptionBuffer, 0, sizeof(s_descriptionBuffer));
            memset(s_scopeBuffer, 0, sizeof(s_scopeBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Active Laws:");
    auto laws = Omniversal::OmniversalTribunalEngine::GetActiveLaws();
    for (const auto& law : laws) {
        ImGui::Text("%s - %s [%s]", law.lawId.c_str(), law.name.c_str(), law.scope.c_str());
    }
}

void OmniversalTribunalPanel::RenderArbitratorManager() {
    ImGui::Text("Cosmic Arbitrator Management");
    ImGui::Separator();
    
    ImGui::InputText("Arbitrator Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Specialization", s_specializationBuffer, sizeof(s_specializationBuffer));
    
    if (ImGui::Button("Appoint Arbitrator")) {
        Omniversal::OmniversalTribunalEngine::AppointCosmicArbitrator(s_nameBuffer, s_specializationBuffer);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_specializationBuffer, 0, sizeof(s_specializationBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Appointed Arbitrators:");
    auto arbitrators = Omniversal::OmniversalTribunalEngine::GetAllArbitrators();
    for (const auto& arbitrator : arbitrators) {
        ImGui::Text("%s - %s (Wisdom: %.2f, Impartiality: %.2f)", arbitrator.arbitratorId.c_str(), 
                    arbitrator.name.c_str(), arbitrator.wisdomScore, arbitrator.impartialityIndex);
    }
}

void OmniversalTribunalPanel::RenderVerdictManager() {
    ImGui::Text("Omniversal Verdict Management");
    ImGui::Separator();
    
    static char caseIdBuffer[128] = {};
    static char courtIdBuffer[128] = {};
    ImGui::InputText("Case ID", caseIdBuffer, sizeof(caseIdBuffer));
    ImGui::InputText("Court ID", courtIdBuffer, sizeof(courtIdBuffer));
    ImGui::InputText("Ruling", s_rulingBuffer, sizeof(s_rulingBuffer));
    ImGui::InputTextMultiline("Judgment (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Issue Verdict")) {
        nlohmann::json judgment = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!judgment.is_discarded()) {
            Omniversal::OmniversalTribunalEngine::IssueOmniversalVerdict(caseIdBuffer, courtIdBuffer, s_rulingBuffer, judgment);
            memset(caseIdBuffer, 0, sizeof(caseIdBuffer));
            memset(courtIdBuffer, 0, sizeof(courtIdBuffer));
            memset(s_rulingBuffer, 0, sizeof(s_rulingBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Issued Verdicts:");
    auto courts = Omniversal::OmniversalTribunalEngine::GetAllCourts();
    for (const auto& court : courts) {
        auto verdicts = Omniversal::OmniversalTribunalEngine::GetVerdictsByCourt(court.courtId);
        for (const auto& verdict : verdicts) {
            ImGui::Text("%s - %s [%s]", verdict.verdictId.c_str(), verdict.caseId.c_str(), verdict.ruling.c_str());
        }
    }
}

void OmniversalTribunalPanel::RenderMetrics() {
    ImGui::Text("Tribunal Metrics");
    ImGui::Separator();
    
    auto metrics = Omniversal::OmniversalTribunalEngine::GetTribunalMetrics();
    
    ImGui::Text("Courts: %d", metrics["courtCount"].get<int>());
    ImGui::Text("Cases: %d", metrics["caseCount"].get<int>());
    ImGui::Text("Laws: %d", metrics["lawCount"].get<int>());
    ImGui::Text("Arbitrators: %d", metrics["arbitratorCount"].get<int>());
    ImGui::Text("Verdicts: %d", metrics["verdictCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Cosmic Justice Index: %.4f", metrics["cosmicJusticeIndex"].get<float>());
    ImGui::Text("Law Adherence: %.4f", metrics["lawAdherence"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void OmniversalTribunalPanel::RenderReport() {
    ImGui::Text("Tribunal Report");
    ImGui::Separator();
    
    auto report = Omniversal::OmniversalTribunalEngine::GenerateTribunalReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool OmniversalTribunalPanel::IsVisible() {
    return s_visible;
}

void OmniversalTribunalPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void OmniversalTribunalPanel::Toggle() {
    s_visible = !s_visible;
}

const char* OmniversalTribunalPanel::GetPanelName() {
    return "Omniversal Tribunal";
}

const char* OmniversalTribunalPanel::GetShortcut() {
    return "Ctrl+Shift+F29";
}

} // namespace IDE
