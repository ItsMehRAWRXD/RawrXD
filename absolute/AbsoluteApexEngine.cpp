#include "absolute/AbsoluteApexEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Absolute {

std::mutex AbsoluteApexEngine::s_mutex;
bool AbsoluteApexEngine::s_initialized = false;
std::map<std::string, UniversalZenith> AbsoluteApexEngine::s_zeniths;
std::map<std::string, CosmicPinnacle> AbsoluteApexEngine::s_pinnacles;
std::map<std::string, MultiversalSummit> AbsoluteApexEngine::s_summits;
std::map<std::string, TranscendentPeak> AbsoluteApexEngine::s_peaks;
std::map<std::string, ApexAchievement> AbsoluteApexEngine::s_achievements;
int64_t AbsoluteApexEngine::s_tickCount = 0;

void AbsoluteApexEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void AbsoluteApexEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_zeniths.clear();
    s_pinnacles.clear();
    s_summits.clear();
    s_peaks.clear();
    s_achievements.clear();
}

std::string AbsoluteApexEngine::AttainUniversalZenith(const std::string& name,
                                                      const std::string& zenithType,
                                                      const std::vector<std::string>& prerequisites) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int zenithCounter = 0;
    std::string zenithId = "universal_zenith_" + std::to_string(++zenithCounter);
    
    UniversalZenith zenith;
    zenith.zenithId = zenithId;
    zenith.name = name;
    zenith.zenithType = zenithType;
    zenith.attainmentLevel = 0.0f;
    zenith.masteryScore = 0.0f;
    zenith.prerequisites = prerequisites;
    zenith.achievedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_zeniths[zenithId] = zenith;
    return zenithId;
}

bool AbsoluteApexEngine::AdvanceZenithAttainment(const std::string& zenithId, float progress) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_zeniths.find(zenithId);
    if (it == s_zeniths.end()) return false;
    it->second.attainmentLevel = std::min(1.0f, it->second.attainmentLevel + progress);
    return true;
}

bool AbsoluteApexEngine::MasterZenith(const std::string& zenithId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_zeniths.find(zenithId);
    if (it == s_zeniths.end()) return false;
    it->second.masteryScore = 1.0f;
    it->second.attainmentLevel = 1.0f;
    return true;
}

UniversalZenith AbsoluteApexEngine::GetZenith(const std::string& zenithId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_zeniths.find(zenithId);
    if (it != s_zeniths.end()) return it->second;
    return UniversalZenith{};
}

std::vector<UniversalZenith> AbsoluteApexEngine::GetAllZeniths() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalZenith> result;
    for (const auto& [id, zenith] : s_zeniths) {
        result.push_back(zenith);
    }
    return result;
}

std::vector<UniversalZenith> AbsoluteApexEngine::GetZenithsByType(const std::string& zenithType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalZenith> result;
    for (const auto& [id, zenith] : s_zeniths) {
        if (zenith.zenithType == zenithType) result.push_back(zenith);
    }
    return result;
}

std::string AbsoluteApexEngine::CommitCosmicPinnacle(const std::string& name,
                                                    const std::string& pinnacleClass,
                                                    const std::map<std::string, float>& attributes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int pinnacleCounter = 0;
    std::string pinnacleId = "cosmic_pinnacle_" + std::to_string(++pinnacleCounter);
    
    CosmicPinnacle pinnacle;
    pinnacle.pinnacleId = pinnacleId;
    pinnacle.name = name;
    pinnacle.pinnacleClass = pinnacleClass;
    pinnacle.elevation = 0.0f;
    pinnacle.stability = 1.0f;
    pinnacle.attributes = attributes;
    pinnacle.committedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_pinnacles[pinnacleId] = pinnacle;
    return pinnacleId;
}

bool AbsoluteApexEngine::ElevatePinnacle(const std::string& pinnacleId, float elevation) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pinnacles.find(pinnacleId);
    if (it == s_pinnacles.end()) return false;
    it->second.elevation += elevation;
    return true;
}

bool AbsoluteApexEngine::StabilizePinnacle(const std::string& pinnacleId, float stability) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pinnacles.find(pinnacleId);
    if (it == s_pinnacles.end()) return false;
    it->second.stability = std::min(1.0f, std::max(0.0f, stability));
    return true;
}

CosmicPinnacle AbsoluteApexEngine::GetPinnacle(const std::string& pinnacleId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_pinnacles.find(pinnacleId);
    if (it != s_pinnacles.end()) return it->second;
    return CosmicPinnacle{};
}

std::vector<CosmicPinnacle> AbsoluteApexEngine::GetAllPinnacles() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicPinnacle> result;
    for (const auto& [id, pinnacle] : s_pinnacles) {
        result.push_back(pinnacle);
    }
    return result;
}

std::vector<CosmicPinnacle> AbsoluteApexEngine::GetPinnaclesByClass(const std::string& pinnacleClass) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicPinnacle> result;
    for (const auto& [id, pinnacle] : s_pinnacles) {
        if (pinnacle.pinnacleClass == pinnacleClass) result.push_back(pinnacle);
    }
    return result;
}

std::string AbsoluteApexEngine::ConveneMultiversalSummit(const std::string& name,
                                                       const std::string& summitCategory,
                                                       const std::vector<std::string>& universes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int summitCounter = 0;
    std::string summitId = "multiversal_summit_" + std::to_string(++summitCounter);
    
    MultiversalSummit summit;
    summit.summitId = summitId;
    summit.name = name;
    summit.summitCategory = summitCategory;
    summit.participatingUniverses = universes;
    summit.convergenceIndex = 1.0f;
    summit.resonanceLevel = 1.0f;
    summit.convenedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_summits[summitId] = summit;
    return summitId;
}

bool AbsoluteApexEngine::HarmonizeSummit(const std::string& summitId, float harmonyBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_summits.find(summitId);
    if (it == s_summits.end()) return false;
    it->second.convergenceIndex = std::min(1.0f, it->second.convergenceIndex + harmonyBoost);
    return true;
}

bool AbsoluteApexEngine::AmplifyResonance(const std::string& summitId, float resonanceBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_summits.find(summitId);
    if (it == s_summits.end()) return false;
    it->second.resonanceLevel = std::min(1.0f, it->second.resonanceLevel + resonanceBoost);
    return true;
}

MultiversalSummit AbsoluteApexEngine::GetSummit(const std::string& summitId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_summits.find(summitId);
    if (it != s_summits.end()) return it->second;
    return MultiversalSummit{};
}

std::vector<MultiversalSummit> AbsoluteApexEngine::GetAllSummits() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalSummit> result;
    for (const auto& [id, summit] : s_summits) {
        result.push_back(summit);
    }
    return result;
}

std::vector<MultiversalSummit> AbsoluteApexEngine::GetSummitsByCategory(const std::string& summitCategory) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalSummit> result;
    for (const auto& [id, summit] : s_summits) {
        if (summit.summitCategory == summitCategory) result.push_back(summit);
    }
    return result;
}

std::string AbsoluteApexEngine::AscendTranscendentPeak(const std::string& name,
                                                     const std::string& peakDomain,
                                                     const std::vector<std::string>& path) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int peakCounter = 0;
    std::string peakId = "transcendent_peak_" + std::to_string(++peakCounter);
    
    TranscendentPeak peak;
    peak.peakId = peakId;
    peak.name = name;
    peak.peakDomain = peakDomain;
    peak.altitude = 0.0f;
    peak.clarity = 0.0f;
    peak.ascensionPath = path;
    peak.ascendedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_peaks[peakId] = peak;
    return peakId;
}

bool AbsoluteApexEngine::ClimbPeak(const std::string& peakId, float altitude) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_peaks.find(peakId);
    if (it == s_peaks.end()) return false;
    it->second.altitude += altitude;
    return true;
}

bool AbsoluteApexEngine::AttainClarity(const std::string& peakId, float clarity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_peaks.find(peakId);
    if (it == s_peaks.end()) return false;
    it->second.clarity = std::min(1.0f, std::max(0.0f, clarity));
    return true;
}

TranscendentPeak AbsoluteApexEngine::GetPeak(const std::string& peakId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_peaks.find(peakId);
    if (it != s_peaks.end()) return it->second;
    return TranscendentPeak{};
}

std::vector<TranscendentPeak> AbsoluteApexEngine::GetAllPeaks() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentPeak> result;
    for (const auto& [id, peak] : s_peaks) {
        result.push_back(peak);
    }
    return result;
}

std::vector<TranscendentPeak> AbsoluteApexEngine::GetPeaksByDomain(const std::string& peakDomain) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentPeak> result;
    for (const auto& [id, peak] : s_peaks) {
        if (peak.peakDomain == peakDomain) result.push_back(peak);
    }
    return result;
}

std::string AbsoluteApexEngine::UnlockApexAchievement(const std::string& name,
                                                      const std::string& achievementTier,
                                                      const nlohmann::json& data) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int achievementCounter = 0;
    std::string achievementId = "apex_achievement_" + std::to_string(++achievementCounter);
    
    ApexAchievement achievement;
    achievement.achievementId = achievementId;
    achievement.name = name;
    achievement.achievementTier = achievementTier;
    achievement.achievementData = data;
    achievement.rarity = 1.0f;
    achievement.prestige = 0.0f;
    achievement.unlockedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_achievements[achievementId] = achievement;
    return achievementId;
}

bool AbsoluteApexEngine::IncreaseAchievementPrestige(const std::string& achievementId, float prestige) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_achievements.find(achievementId);
    if (it == s_achievements.end()) return false;
    it->second.prestige = std::min(1.0f, it->second.prestige + prestige);
    return true;
}

ApexAchievement AbsoluteApexEngine::GetAchievement(const std::string& achievementId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_achievements.find(achievementId);
    if (it != s_achievements.end()) return it->second;
    return ApexAchievement{};
}

std::vector<ApexAchievement> AbsoluteApexEngine::GetAllAchievements() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ApexAchievement> result;
    for (const auto& [id, achievement] : s_achievements) {
        result.push_back(achievement);
    }
    return result;
}

std::vector<ApexAchievement> AbsoluteApexEngine::GetAchievementsByTier(const std::string& achievementTier) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<ApexAchievement> result;
    for (const auto& [id, achievement] : s_achievements) {
        if (achievement.achievementTier == achievementTier) result.push_back(achievement);
    }
    return result;
}

float AbsoluteApexEngine::CalculateTotalAttainment() {
    std::lock_guard<std::mutex> lock(s_mutex);
    float totalAttainment = 0.0f;
    for (const auto& [id, zenith] : s_zeniths) {
        totalAttainment += zenith.attainmentLevel;
    }
    for (const auto& [id, pinnacle] : s_pinnacles) {
        totalAttainment += pinnacle.elevation / 1000.0f;
    }
    return totalAttainment;
}

float AbsoluteApexEngine::CalculateApexElevation() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_peaks.empty()) return 0.0f;
    float totalAltitude = 0.0f;
    for (const auto& [id, peak] : s_peaks) {
        totalAltitude += peak.altitude;
    }
    return totalAltitude / s_peaks.size();
}

nlohmann::json AbsoluteApexEngine::GetApexMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["zenithCount"] = s_zeniths.size();
    metrics["pinnacleCount"] = s_pinnacles.size();
    metrics["summitCount"] = s_summits.size();
    metrics["peakCount"] = s_peaks.size();
    metrics["achievementCount"] = s_achievements.size();
    metrics["totalAttainment"] = CalculateTotalAttainment();
    metrics["apexElevation"] = CalculateApexElevation();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json AbsoluteApexEngine::GenerateApexReport() {
    nlohmann::json report;
    report["metrics"] = GetApexMetrics();
    report["attainedZeniths"] = nlohmann::json::array();
    report["committedPinnacles"] = nlohmann::json::array();
    report["convenedSummits"] = nlohmann::json::array();
    report["ascendedPeaks"] = nlohmann::json::array();
    report["unlockedAchievements"] = nlohmann::json::array();
    
    for (const auto& zenith : GetAllZeniths()) {
        nlohmann::json z;
        z["id"] = zenith.zenithId;
        z["name"] = zenith.name;
        z["type"] = zenith.zenithType;
        z["attainment"] = zenith.attainmentLevel;
        z["mastery"] = zenith.masteryScore;
        report["attainedZeniths"].push_back(z);
    }
    
    for (const auto& pinnacle : GetAllPinnacles()) {
        nlohmann::json p;
        p["id"] = pinnacle.pinnacleId;
        p["name"] = pinnacle.name;
        p["class"] = pinnacle.pinnacleClass;
        p["elevation"] = pinnacle.elevation;
        p["stability"] = pinnacle.stability;
        report["committedPinnacles"].push_back(p);
    }
    
    for (const auto& summit : GetAllSummits()) {
        nlohmann::json s;
        s["id"] = summit.summitId;
        s["name"] = summit.name;
        s["category"] = summit.summitCategory;
        s["convergence"] = summit.convergenceIndex;
        s["resonance"] = summit.resonanceLevel;
        report["convenedSummits"].push_back(s);
    }
    
    for (const auto& peak : GetAllPeaks()) {
        nlohmann::json p;
        p["id"] = peak.peakId;
        p["name"] = peak.name;
        p["domain"] = peak.peakDomain;
        p["altitude"] = peak.altitude;
        p["clarity"] = peak.clarity;
        report["ascendedPeaks"].push_back(p);
    }
    
    for (const auto& achievement : GetAllAchievements()) {
        nlohmann::json a;
        a["id"] = achievement.achievementId;
        a["name"] = achievement.name;
        a["tier"] = achievement.achievementTier;
        a["rarity"] = achievement.rarity;
        a["prestige"] = achievement.prestige;
        report["unlockedAchievements"].push_back(a);
    }
    
    return report;
}

void AbsoluteApexEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, zenith] : s_zeniths) {
        if (zenith.attainmentLevel < 1.0f) {
            zenith.attainmentLevel = std::min(1.0f, zenith.attainmentLevel + 0.0001f);
        }
    }
    
    for (auto& [id, pinnacle] : s_pinnacles) {
        pinnacle.stability *= 0.9999f;
        pinnacle.stability += 0.0001f;
    }
    
    for (auto& [id, summit] : s_summits) {
        summit.convergenceIndex *= 0.9999f;
        summit.convergenceIndex += 0.0001f;
        summit.resonanceLevel *= 0.9999f;
        summit.resonanceLevel += 0.0001f;
    }
    
    for (auto& [id, peak] : s_peaks) {
        if (peak.clarity < 1.0f) {
            peak.clarity = std::min(1.0f, peak.clarity + 0.0001f);
        }
    }
}

bool AbsoluteApexEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Absolute
