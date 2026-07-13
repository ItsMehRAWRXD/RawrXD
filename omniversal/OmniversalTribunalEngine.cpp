#include "omniversal/OmniversalTribunalEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Omniversal {

std::mutex OmniversalTribunalEngine::s_mutex;
bool OmniversalTribunalEngine::s_initialized = false;
std::map<std::string, OmniversalCourt> OmniversalTribunalEngine::s_courts;
std::map<std::string, CosmicJusticeCase> OmniversalTribunalEngine::s_cases;
std::map<std::string, MultiversalLaw> OmniversalTribunalEngine::s_laws;
std::map<std::string, CosmicArbitrator> OmniversalTribunalEngine::s_arbitrators;
std::map<std::string, OmniversalVerdict> OmniversalTribunalEngine::s_verdicts;
int64_t OmniversalTribunalEngine::s_tickCount = 0;

void OmniversalTribunalEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void OmniversalTribunalEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_courts.clear();
    s_cases.clear();
    s_laws.clear();
    s_arbitrators.clear();
    s_verdicts.clear();
}

std::string OmniversalTribunalEngine::EstablishOmniversalCourt(const std::string& name,
                                                               const std::string& jurisdiction,
                                                               const std::vector<std::string>& universes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int courtCounter = 0;
    std::string courtId = "omniversal_court_" + std::to_string(++courtCounter);
    
    OmniversalCourt court;
    court.courtId = courtId;
    court.name = name;
    court.jurisdiction = jurisdiction;
    court.memberUniverses = universes;
    court.authorityLevel = 1.0f;
    court.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_courts[courtId] = court;
    return courtId;
}

bool OmniversalTribunalEngine::DissolveCourt(const std::string& courtId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_courts.find(courtId);
    if (it == s_courts.end()) return false;
    s_courts.erase(it);
    return true;
}

OmniversalCourt OmniversalTribunalEngine::GetCourt(const std::string& courtId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_courts.find(courtId);
    if (it != s_courts.end()) return it->second;
    return OmniversalCourt{};
}

std::vector<OmniversalCourt> OmniversalTribunalEngine::GetAllCourts() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<OmniversalCourt> result;
    for (const auto& [id, court] : s_courts) {
        result.push_back(court);
    }
    return result;
}

std::string OmniversalTribunalEngine::FileCosmicJusticeCase(const std::string& title,
                                                           const std::string& description,
                                                           const std::string& plaintiff,
                                                           const std::string& defendant) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int caseCounter = 0;
    std::string caseId = "cosmic_case_" + std::to_string(++caseCounter);
    
    CosmicJusticeCase caseData;
    caseData.caseId = caseId;
    caseData.title = title;
    caseData.description = description;
    caseData.plaintiff = plaintiff;
    caseData.defendant = defendant;
    caseData.status = "filed";
    caseData.filedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_cases[caseId] = caseData;
    return caseId;
}

bool OmniversalTribunalEngine::UpdateCaseStatus(const std::string& caseId, const std::string& status) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_cases.find(caseId);
    if (it == s_cases.end()) return false;
    it->second.status = status;
    if (status == "judged") {
        it->second.judgedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    return true;
}

bool OmniversalTribunalEngine::SubmitEvidence(const std::string& caseId, const nlohmann::json& evidence) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_cases.find(caseId);
    if (it == s_cases.end()) return false;
    it->second.evidence = evidence;
    return true;
}

CosmicJusticeCase OmniversalTribunalEngine::GetCase(const std::string& caseId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_cases.find(caseId);
    if (it != s_cases.end()) return it->second;
    return CosmicJusticeCase{};
}

std::vector<CosmicJusticeCase> OmniversalTribunalEngine::GetAllCases() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicJusticeCase> result;
    for (const auto& [id, caseData] : s_cases) {
        result.push_back(caseData);
    }
    return result;
}

std::vector<CosmicJusticeCase> OmniversalTribunalEngine::GetCasesByStatus(const std::string& status) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicJusticeCase> result;
    for (const auto& [id, caseData] : s_cases) {
        if (caseData.status == status) {
            result.push_back(caseData);
        }
    }
    return result;
}

std::string OmniversalTribunalEngine::EnactMultiversalLaw(const std::string& name,
                                                           const std::string& description,
                                                           const std::string& scope,
                                                           const nlohmann::json& provisions) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int lawCounter = 0;
    std::string lawId = "multiversal_law_" + std::to_string(++lawCounter);
    
    MultiversalLaw law;
    law.lawId = lawId;
    law.name = name;
    law.description = description;
    law.scope = scope;
    law.provisions = provisions;
    law.enforcementPriority = 1.0f;
    law.active = true;
    law.enactedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_laws[lawId] = law;
    return lawId;
}

bool OmniversalTribunalEngine::AmendLaw(const std::string& lawId, const nlohmann::json& amendments) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_laws.find(lawId);
    if (it == s_laws.end()) return false;
    for (auto& [key, value] : amendments.items()) {
        it->second.provisions[key] = value;
    }
    return true;
}

bool OmniversalTribunalEngine::RepealLaw(const std::string& lawId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_laws.find(lawId);
    if (it == s_laws.end()) return false;
    it->second.active = false;
    return true;
}

MultiversalLaw OmniversalTribunalEngine::GetLaw(const std::string& lawId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_laws.find(lawId);
    if (it != s_laws.end()) return it->second;
    return MultiversalLaw{};
}

std::vector<MultiversalLaw> OmniversalTribunalEngine::GetAllLaws() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalLaw> result;
    for (const auto& [id, law] : s_laws) {
        result.push_back(law);
    }
    return result;
}

std::vector<MultiversalLaw> OmniversalTribunalEngine::GetActiveLaws() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalLaw> result;
    for (const auto& [id, law] : s_laws) {
        if (law.active) result.push_back(law);
    }
    return result;
}

std::string OmniversalTribunalEngine::AppointCosmicArbitrator(const std::string& name,
                                                              const std::string& specialization) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int arbitratorCounter = 0;
    std::string arbitratorId = "arbitrator_" + std::to_string(++arbitratorCounter);
    
    CosmicArbitrator arbitrator;
    arbitrator.arbitratorId = arbitratorId;
    arbitrator.name = name;
    arbitrator.specialization = specialization;
    arbitrator.wisdomScore = 1.0f;
    arbitrator.impartialityIndex = 1.0f;
    arbitrator.appointedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_arbitrators[arbitratorId] = arbitrator;
    return arbitratorId;
}

bool OmniversalTribunalEngine::AssignArbitratorToCase(const std::string& arbitratorId, const std::string& caseId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto arbIt = s_arbitrators.find(arbitratorId);
    auto caseIt = s_cases.find(caseId);
    if (arbIt == s_arbitrators.end() || caseIt == s_cases.end()) return false;
    arbIt->second.caseHistory.push_back(caseId);
    return true;
}

bool OmniversalTribunalEngine::RateArbitrator(const std::string& arbitratorId, float wisdomRating, float impartialityRating) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_arbitrators.find(arbitratorId);
    if (it == s_arbitrators.end()) return false;
    it->second.wisdomScore = (it->second.wisdomScore + wisdomRating) / 2.0f;
    it->second.impartialityIndex = (it->second.impartialityIndex + impartialityRating) / 2.0f;
    return true;
}

CosmicArbitrator OmniversalTribunalEngine::GetArbitrator(const std::string& arbitratorId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_arbitrators.find(arbitratorId);
    if (it != s_arbitrators.end()) return it->second;
    return CosmicArbitrator{};
}

std::vector<CosmicArbitrator> OmniversalTribunalEngine::GetAllArbitrators() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicArbitrator> result;
    for (const auto& [id, arbitrator] : s_arbitrators) {
        result.push_back(arbitrator);
    }
    return result;
}

std::string OmniversalTribunalEngine::IssueOmniversalVerdict(const std::string& caseId,
                                                               const std::string& courtId,
                                                               const std::string& ruling,
                                                               const nlohmann::json& judgment) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int verdictCounter = 0;
    std::string verdictId = "verdict_" + std::to_string(++verdictCounter);
    
    OmniversalVerdict verdict;
    verdict.verdictId = verdictId;
    verdict.caseId = caseId;
    verdict.courtId = courtId;
    verdict.ruling = ruling;
    verdict.judgment = judgment;
    verdict.issuedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_verdicts[verdictId] = verdict;
    
    auto caseIt = s_cases.find(caseId);
    if (caseIt != s_cases.end()) {
        caseIt->second.status = "judged";
        caseIt->second.verdict = judgment;
        caseIt->second.judgedTimestamp = verdict.issuedTimestamp;
    }
    
    return verdictId;
}

bool OmniversalTribunalEngine::AppealVerdict(const std::string& verdictId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_verdicts.find(verdictId);
    if (it == s_verdicts.end()) return false;
    auto caseIt = s_cases.find(it->second.caseId);
    if (caseIt != s_cases.end()) {
        caseIt->second.status = "appealed";
    }
    return true;
}

bool OmniversalTribunalEngine::ExecuteVerdict(const std::string& verdictId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_verdicts.find(verdictId);
    if (it == s_verdicts.end()) return false;
    auto caseIt = s_cases.find(it->second.caseId);
    if (caseIt != s_cases.end()) {
        caseIt->second.status = "executed";
    }
    return true;
}

OmniversalVerdict OmniversalTribunalEngine::GetVerdict(const std::string& verdictId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_verdicts.find(verdictId);
    if (it != s_verdicts.end()) return it->second;
    return OmniversalVerdict{};
}

std::vector<OmniversalVerdict> OmniversalTribunalEngine::GetVerdictsByCourt(const std::string& courtId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<OmniversalVerdict> result;
    for (const auto& [id, verdict] : s_verdicts) {
        if (verdict.courtId == courtId) result.push_back(verdict);
    }
    return result;
}

float OmniversalTribunalEngine::CalculateCosmicJusticeIndex() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_cases.empty()) return 1.0f;
    int judgedCases = 0;
    for (const auto& [id, caseData] : s_cases) {
        if (caseData.status == "judged" || caseData.status == "executed") judgedCases++;
    }
    return static_cast<float>(judgedCases) / s_cases.size();
}

float OmniversalTribunalEngine::CalculateMultiversalLawAdherence() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_laws.empty()) return 1.0f;
    int activeLaws = 0;
    for (const auto& [id, law] : s_laws) {
        if (law.active) activeLaws++;
    }
    return static_cast<float>(activeLaws) / s_laws.size();
}

nlohmann::json OmniversalTribunalEngine::GetTribunalMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["courtCount"] = s_courts.size();
    metrics["caseCount"] = s_cases.size();
    metrics["lawCount"] = s_laws.size();
    metrics["arbitratorCount"] = s_arbitrators.size();
    metrics["verdictCount"] = s_verdicts.size();
    metrics["cosmicJusticeIndex"] = CalculateCosmicJusticeIndex();
    metrics["lawAdherence"] = CalculateMultiversalLawAdherence();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json OmniversalTribunalEngine::GenerateTribunalReport() {
    nlohmann::json report;
    report["metrics"] = GetTribunalMetrics();
    report["courts"] = nlohmann::json::array();
    report["pendingCases"] = nlohmann::json::array();
    report["activeLaws"] = nlohmann::json::array();
    
    for (const auto& court : GetAllCourts()) {
        nlohmann::json c;
        c["id"] = court.courtId;
        c["name"] = court.name;
        c["jurisdiction"] = court.jurisdiction;
        c["authorityLevel"] = court.authorityLevel;
        report["courts"].push_back(c);
    }
    
    for (const auto& caseData : GetCasesByStatus("filed")) {
        nlohmann::json c;
        c["id"] = caseData.caseId;
        c["title"] = caseData.title;
        c["plaintiff"] = caseData.plaintiff;
        c["defendant"] = caseData.defendant;
        report["pendingCases"].push_back(c);
    }
    
    return report;
}

void OmniversalTribunalEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, court] : s_courts) {
        court.authorityLevel *= 0.9999f;
        court.authorityLevel += 0.0001f;
    }
}

bool OmniversalTribunalEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Omniversal
