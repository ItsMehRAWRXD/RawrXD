#pragma once
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Omniversal {

struct OmniversalCourt {
    std::string courtId;
    std::string name;
    std::string jurisdiction; // "omniversal", "multi_universal", "cosmic"
    std::vector<std::string> memberUniverses;
    float authorityLevel;
    int64_t establishedTimestamp;
};

struct CosmicJusticeCase {
    std::string caseId;
    std::string title;
    std::string description;
    std::string plaintiff;
    std::string defendant;
    std::string status; // "filed", "hearing", "deliberation", "judged", "appealed"
    nlohmann::json evidence;
    nlohmann::json verdict;
    int64_t filedTimestamp;
    int64_t judgedTimestamp;
};

struct MultiversalLaw {
    std::string lawId;
    std::string name;
    std::string description;
    std::string scope; // "omniversal", "multiversal", "universal"
    nlohmann::json provisions;
    float enforcementPriority;
    bool active;
    int64_t enactedTimestamp;
};

struct CosmicArbitrator {
    std::string arbitratorId;
    std::string name;
    std::string specialization;
    float wisdomScore;
    float impartialityIndex;
    std::vector<std::string> caseHistory;
    int64_t appointedTimestamp;
};

struct OmniversalVerdict {
    std::string verdictId;
    std::string caseId;
    std::string courtId;
    std::string ruling; // "guilty", "innocent", "settled", "dismissed"
    nlohmann::json judgment;
    std::map<std::string, float> penalties;
    std::map<std::string, float> restitutions;
    int64_t issuedTimestamp;
};

class OmniversalTribunalEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string EstablishOmniversalCourt(const std::string& name,
                                                const std::string& jurisdiction,
                                                const std::vector<std::string>& universes);
    static bool DissolveCourt(const std::string& courtId);
    static OmniversalCourt GetCourt(const std::string& courtId);
    static std::vector<OmniversalCourt> GetAllCourts();
    
    static std::string FileCosmicJusticeCase(const std::string& title,
                                              const std::string& description,
                                              const std::string& plaintiff,
                                              const std::string& defendant);
    static bool UpdateCaseStatus(const std::string& caseId, const std::string& status);
    static bool SubmitEvidence(const std::string& caseId, const nlohmann::json& evidence);
    static CosmicJusticeCase GetCase(const std::string& caseId);
    static std::vector<CosmicJusticeCase> GetAllCases();
    static std::vector<CosmicJusticeCase> GetCasesByStatus(const std::string& status);
    
    static std::string EnactMultiversalLaw(const std::string& name,
                                           const std::string& description,
                                           const std::string& scope,
                                           const nlohmann::json& provisions);
    static bool AmendLaw(const std::string& lawId, const nlohmann::json& amendments);
    static bool RepealLaw(const std::string& lawId);
    static MultiversalLaw GetLaw(const std::string& lawId);
    static std::vector<MultiversalLaw> GetAllLaws();
    static std::vector<MultiversalLaw> GetActiveLaws();
    
    static std::string AppointCosmicArbitrator(const std::string& name,
                                               const std::string& specialization);
    static bool AssignArbitratorToCase(const std::string& arbitratorId, const std::string& caseId);
    static bool RateArbitrator(const std::string& arbitratorId, float wisdomRating, float impartialityRating);
    static CosmicArbitrator GetArbitrator(const std::string& arbitratorId);
    static std::vector<CosmicArbitrator> GetAllArbitrators();
    
    static std::string IssueOmniversalVerdict(const std::string& caseId,
                                              const std::string& courtId,
                                              const std::string& ruling,
                                              const nlohmann::json& judgment);
    static bool AppealVerdict(const std::string& verdictId);
    static bool ExecuteVerdict(const std::string& verdictId);
    static OmniversalVerdict GetVerdict(const std::string& verdictId);
    static std::vector<OmniversalVerdict> GetVerdictsByCourt(const std::string& courtId);
    
    static float CalculateCosmicJusticeIndex();
    static float CalculateMultiversalLawAdherence();
    static nlohmann::json GetTribunalMetrics();
    static nlohmann::json GenerateTribunalReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, OmniversalCourt> s_courts;
    static std::map<std::string, CosmicJusticeCase> s_cases;
    static std::map<std::string, MultiversalLaw> s_laws;
    static std::map<std::string, CosmicArbitrator> s_arbitrators;
    static std::map<std::string, OmniversalVerdict> s_verdicts;
    static int64_t s_tickCount;
};

} // namespace Omniversal
