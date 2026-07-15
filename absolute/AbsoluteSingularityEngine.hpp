#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Absolute {

struct AbsolutePoint {
    std::string pointId;
    std::string name;
    float absoluteness;
    float uniqueness;
    float irreducibility;
    int64_t definedTimestamp;
    std::map<std::string, nlohmann::json> properties;
};

struct UltimateConvergence {
    std::string convergenceId;
    std::string name;
    float convergence;
    float unity;
    float singularity;
    int64_t achievedTimestamp;
    std::vector<std::string> convergedPoints;
};

struct PerfectState {
    std::string stateId;
    std::string name;
    float perfection;
    float stability;
    float completeness;
    int64_t attainedTimestamp;
    bool isMaintained;
};

struct ImmutableTruth {
    std::string truthId;
    std::string name;
    std::string statement;
    float veracity;
    float universality;
    float eternality;
    int64_t discoveredTimestamp;
    bool isVerified;
};

struct FinalCause {
    std::string causeId;
    std::string name;
    std::string purpose;
    float significance;
    float necessity;
    float sufficiency;
    int64_t determinedTimestamp;
    bool isAchieved;
};

class AbsoluteSingularityEngine {
public:
    static void Init();
    static void Shutdown();

    // Absolute Point Management
    static std::string DefineAbsolutePoint(const std::string& name);
    static bool IncreaseAbsoluteness(const std::string& pointId, float absoluteness);
    static bool EnsureUniqueness(const std::string& pointId, float uniqueness);
    static bool GuaranteeIrreducibility(const std::string& pointId, float irreducibility);
    static bool SetProperty(const std::string& pointId, const std::string& key, const nlohmann::json& value);
    static AbsolutePoint GetPoint(const std::string& pointId);
    static std::vector<AbsolutePoint> GetAllPoints();

    // Ultimate Convergence Management
    static std::string AchieveConvergence(const std::string& name);
    static bool DeepenConvergence(const std::string& convergenceId, float convergence);
    static bool StrengthenUnity(const std::string& convergenceId, float unity);
    static bool IntensifySingularity(const std::string& convergenceId, float singularity);
    static bool ConvergePoint(const std::string& convergenceId, const std::string& pointId);
    static UltimateConvergence GetConvergence(const std::string& convergenceId);
    static std::vector<UltimateConvergence> GetAllConvergences();

    // Perfect State Management
    static std::string AttainPerfectState(const std::string& name);
    static bool PerfectPerfection(const std::string& stateId, float perfection);
    static bool StabilizeState(const std::string& stateId, float stability);
    static bool CompleteState(const std::string& stateId, float completeness);
    static bool MaintainState(const std::string& stateId);
    static bool ReleaseState(const std::string& stateId);
    static PerfectState GetState(const std::string& stateId);
    static std::vector<PerfectState> GetAllStates();

    // Immutable Truth Management
    static std::string DiscoverTruth(const std::string& name, const std::string& statement);
    static bool VerifyTruth(const std::string& truthId, float veracity);
    static bool UniversalizeTruth(const std::string& truthId, float universality);
    static bool EternalizeTruth(const std::string& truthId, float eternality);
    static bool ConfirmTruth(const std::string& truthId);
    static ImmutableTruth GetTruth(const std::string& truthId);
    static std::vector<ImmutableTruth> GetAllTruths();

    // Final Cause Management
    static std::string DetermineFinalCause(const std::string& name, const std::string& purpose);
    static bool SignifyCause(const std::string& causeId, float significance);
    static bool EnsureNecessity(const std::string& causeId, float necessity);
    static bool GuaranteeSufficiency(const std::string& causeId, float sufficiency);
    static bool AchieveCause(const std::string& causeId);
    static FinalCause GetCause(const std::string& causeId);
    static std::vector<FinalCause> GetAllCauses();

    // Absolute Metrics
    static float CalculateTotalAbsoluteness();
    static float CalculateAverageConvergence();
    static int GetVerifiedTruthCount();
    static int getAchievedCauseCount();
    static nlohmann::json GetAbsoluteMetrics();
    static nlohmann::json GenerateAbsoluteReport();

    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, AbsolutePoint> s_points;
    static std::map<std::string, UltimateConvergence> s_convergences;
    static std::map<std::string, PerfectState> s_states;
    static std::map<std::string, ImmutableTruth> s_truths;
    static std::map<std::string, FinalCause> s_causes;
    static int64_t s_tickCount;
};

} // namespace Absolute
