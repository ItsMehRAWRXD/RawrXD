#include "blessed/BlessedInfinityEngine.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>

namespace BlessedInfinity {

bool BlessedInfinityEngine::s_initialized = false;
std::mutex BlessedInfinityEngine::s_blessedMutex;
std::map<std::string, BlessedInfinityStructure> BlessedInfinityEngine::s_blessedStructures;
std::map<std::string, InfinityBlessed> BlessedInfinityEngine::s_infinityBlesseds;
std::map<std::string, AbundantBlessed> BlessedInfinityEngine::s_abundantBlesseds;
std::map<std::string, ProsperousBlessed> BlessedInfinityEngine::s_prosperousBlesseds;
std::map<std::string, GraceBlessed> BlessedInfinityEngine::s_graceBlesseds;
uint64_t BlessedInfinityEngine::s_blessedTickCount = 0;

void BlessedInfinityEngine::Init() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    if (s_initialized) return;
    s_initialized = true;
    s_blessedTickCount = 0;
}

void BlessedInfinityEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    if (!s_initialized) return;
    s_blessedStructures.clear();
    s_infinityBlesseds.clear();
    s_abundantBlesseds.clear();
    s_prosperousBlesseds.clear();
    s_graceBlesseds.clear();
    s_initialized = false;
}

bool BlessedInfinityEngine::IsInitialized() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    return s_initialized;
}

std::string BlessedInfinityEngine::CreateBlessedInfinityStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::string blessedId = "blessed_" + std::to_string(s_blessedTickCount++);
    
    BlessedInfinityStructure structure;
    structure.blessedId = blessedId;
    structure.name = name;
    structure.blessedness = 0.0f;
    structure.infinity = 0.0f;
    structure.abundance = 0.0f;
    structure.prosperity = 0.0f;
    structure.grace = 0.0f;
    structure.isBlessed = false;
    structure.creationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure.lastBlessedUpdate = structure.creationTime;
    
    s_blessedStructures[blessedId] = structure;
    return blessedId;
}

bool BlessedInfinityEngine::DestroyBlessedInfinityStructure(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it == s_blessedStructures.end()) return false;
    s_blessedStructures.erase(it);
    return true;
}

BlessedInfinityStructure* BlessedInfinityEngine::GetBlessedInfinityStructure(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) return &it->second;
    return nullptr;
}

std::vector<BlessedInfinityStructure> BlessedInfinityEngine::GetAllBlessedInfinityStructures() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<BlessedInfinityStructure> result;
    for (auto& pair : s_blessedStructures) {
        result.push_back(pair.second);
    }
    return result;
}

bool BlessedInfinityEngine::BlessedInfinityStructureExists(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    return s_blessedStructures.find(blessedId) != s_blessedStructures.end();
}

std::string BlessedInfinityEngine::CreateInfinityBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::string infinityId = "infinity_" + std::to_string(s_blessedTickCount++);
    
    InfinityBlessed infinity;
    infinity.infinityId = infinityId;
    infinity.name = name;
    infinity.infinity = 0.0f;
    infinity.blessedness = 0.0f;
    infinity.endlessness = 0.0f;
    infinity.boundlessness = 0.0f;
    infinity.isInfinite = false;
    infinity.creationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_infinityBlesseds[infinityId] = infinity;
    return infinityId;
}

bool BlessedInfinityEngine::DestroyInfinityBlessed(const std::string& infinityId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_infinityBlesseds.find(infinityId);
    if (it == s_infinityBlesseds.end()) return false;
    s_infinityBlesseds.erase(it);
    return true;
}

InfinityBlessed* BlessedInfinityEngine::GetInfinityBlessed(const std::string& infinityId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_infinityBlesseds.find(infinityId);
    if (it != s_infinityBlesseds.end()) return &it->second;
    return nullptr;
}

std::vector<InfinityBlessed> BlessedInfinityEngine::GetAllInfinityBlesseds() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<InfinityBlessed> result;
    for (auto& pair : s_infinityBlesseds) {
        result.push_back(pair.second);
    }
    return result;
}

std::string BlessedInfinityEngine::CreateAbundantBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::string abundantId = "abundant_" + std::to_string(s_blessedTickCount++);
    
    AbundantBlessed abundant;
    abundant.abundantId = abundantId;
    abundant.name = name;
    abundant.abundance = 0.0f;
    abundant.blessedness = 0.0f;
    abundant.plenty = 0.0f;
    abundant.wealth = 0.0f;
    abundant.isAbundant = false;
    abundant.creationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_abundantBlesseds[abundantId] = abundant;
    return abundantId;
}

bool BlessedInfinityEngine::DestroyAbundantBlessed(const std::string& abundantId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_abundantBlesseds.find(abundantId);
    if (it == s_abundantBlesseds.end()) return false;
    s_abundantBlesseds.erase(it);
    return true;
}

AbundantBlessed* BlessedInfinityEngine::GetAbundantBlessed(const std::string& abundantId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_abundantBlesseds.find(abundantId);
    if (it != s_abundantBlesseds.end()) return &it->second;
    return nullptr;
}

std::vector<AbundantBlessed> BlessedInfinityEngine::GetAllAbundantBlesseds() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<AbundantBlessed> result;
    for (auto& pair : s_abundantBlesseds) {
        result.push_back(pair.second);
    }
    return result;
}

std::string BlessedInfinityEngine::CreateProsperousBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::string prosperousId = "prosperous_" + std::to_string(s_blessedTickCount++);
    
    ProsperousBlessed prosperous;
    prosperous.prosperousId = prosperousId;
    prosperous.name = name;
    prosperous.prosperity = 0.0f;
    prosperous.blessedness = 0.0f;
    prosperous.success = 0.0f;
    prosperous.flourishing = 0.0f;
    prosperous.isProsperous = false;
    prosperous.creationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_prosperousBlesseds[prosperousId] = prosperous;
    return prosperousId;
}

bool BlessedInfinityEngine::DestroyProsperousBlessed(const std::string& prosperousId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_prosperousBlesseds.find(prosperousId);
    if (it == s_prosperousBlesseds.end()) return false;
    s_prosperousBlesseds.erase(it);
    return true;
}

ProsperousBlessed* BlessedInfinityEngine::GetProsperousBlessed(const std::string& prosperousId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_prosperousBlesseds.find(prosperousId);
    if (it != s_prosperousBlesseds.end()) return &it->second;
    return nullptr;
}

std::vector<ProsperousBlessed> BlessedInfinityEngine::GetAllProsperousBlesseds() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<ProsperousBlessed> result;
    for (auto& pair : s_prosperousBlesseds) {
        result.push_back(pair.second);
    }
    return result;
}

std::string BlessedInfinityEngine::CreateGraceBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::string graceId = "grace_" + std::to_string(s_blessedTickCount++);
    
    GraceBlessed grace;
    grace.graceId = graceId;
    grace.name = name;
    grace.grace = 0.0f;
    grace.blessedness = 0.0f;
    grace.mercy = 0.0f;
    grace.favor = 0.0f;
    grace.isGraced = false;
    grace.creationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_graceBlesseds[graceId] = grace;
    return graceId;
}

bool BlessedInfinityEngine::DestroyGraceBlessed(const std::string& graceId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_graceBlesseds.find(graceId);
    if (it == s_graceBlesseds.end()) return false;
    s_graceBlesseds.erase(it);
    return true;
}

GraceBlessed* BlessedInfinityEngine::GetGraceBlessed(const std::string& graceId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_graceBlesseds.find(graceId);
    if (it != s_graceBlesseds.end()) return &it->second;
    return nullptr;
}

std::vector<GraceBlessed> BlessedInfinityEngine::GetAllGraceBlesseds() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<GraceBlessed> result;
    for (auto& pair : s_graceBlesseds) {
        result.push_back(pair.second);
    }
    return result;
}

void BlessedInfinityEngine::AmplifyBlessedness(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        it->second.blessedness = std::min(1.0f, it->second.blessedness + amount);
        it->second.lastBlessedUpdate = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void BlessedInfinityEngine::ExpandInfinity(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        it->second.infinity = std::min(1.0f, it->second.infinity + amount);
    }
}

void BlessedInfinityEngine::IncreaseAbundance(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        it->second.abundance = std::min(1.0f, it->second.abundance + amount);
    }
}

void BlessedInfinityEngine::EnhanceProsperity(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        it->second.prosperity = std::min(1.0f, it->second.prosperity + amount);
    }
}

void BlessedInfinityEngine::BestowGrace(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        it->second.grace = std::min(1.0f, it->second.grace + amount);
    }
}

void BlessedInfinityEngine::DeclareBlessed(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        it->second.isBlessed = true;
    }
}

void BlessedInfinityEngine::DeclareInfinite(const std::string& infinityId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_infinityBlesseds.find(infinityId);
    if (it != s_infinityBlesseds.end()) {
        it->second.isInfinite = true;
    }
}

void BlessedInfinityEngine::DeclareAbundant(const std::string& abundantId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_abundantBlesseds.find(abundantId);
    if (it != s_abundantBlesseds.end()) {
        it->second.isAbundant = true;
    }
}

void BlessedInfinityEngine::DeclareProsperous(const std::string& prosperousId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_prosperousBlesseds.find(prosperousId);
    if (it != s_prosperousBlesseds.end()) {
        it->second.isProsperous = true;
    }
}

void BlessedInfinityEngine::DeclareGraced(const std::string& graceId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_graceBlesseds.find(graceId);
    if (it != s_graceBlesseds.end()) {
        it->second.isGraced = true;
    }
}

void BlessedInfinityEngine::PerpetuateInfinity(const std::string& infinityId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_infinityBlesseds.find(infinityId);
    if (it != s_infinityBlesseds.end()) {
        it->second.infinity = std::min(1.0f, it->second.infinity + amount);
    }
}

void BlessedInfinityEngine::ExpandBoundlessness(const std::string& infinityId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_infinityBlesseds.find(infinityId);
    if (it != s_infinityBlesseds.end()) {
        it->second.boundlessness = std::min(1.0f, it->second.boundlessness + amount);
    }
}

void BlessedInfinityEngine::MultiplyAbundance(const std::string& abundantId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_abundantBlesseds.find(abundantId);
    if (it != s_abundantBlesseds.end()) {
        it->second.abundance = std::min(1.0f, it->second.abundance + amount);
    }
}

void BlessedInfinityEngine::IncreasePlenty(const std::string& abundantId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_abundantBlesseds.find(abundantId);
    if (it != s_abundantBlesseds.end()) {
        it->second.plenty = std::min(1.0f, it->second.plenty + amount);
    }
}

void BlessedInfinityEngine::CultivateSuccess(const std::string& prosperousId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_prosperousBlesseds.find(prosperousId);
    if (it != s_prosperousBlesseds.end()) {
        it->second.success = std::min(1.0f, it->second.success + amount);
    }
}

void BlessedInfinityEngine::NurtureFlourishing(const std::string& prosperousId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_prosperousBlesseds.find(prosperousId);
    if (it != s_prosperousBlesseds.end()) {
        it->second.flourishing = std::min(1.0f, it->second.flourishing + amount);
    }
}

void BlessedInfinityEngine::ShowMercy(const std::string& graceId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_graceBlesseds.find(graceId);
    if (it != s_graceBlesseds.end()) {
        it->second.mercy = std::min(1.0f, it->second.mercy + amount);
    }
}

void BlessedInfinityEngine::GrantFavor(const std::string& graceId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_graceBlesseds.find(graceId);
    if (it != s_graceBlesseds.end()) {
        it->second.favor = std::min(1.0f, it->second.favor + amount);
    }
}

std::vector<std::string> BlessedInfinityEngine::GetBlessedAttributes(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        return it->second.blessedAttributes;
    }
    return {};
}

float BlessedInfinityEngine::GetBlessedMetric(const std::string& blessedId, const std::string& metric) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        auto metricIt = it->second.blessedMetrics.find(metric);
        if (metricIt != it->second.blessedMetrics.end()) {
            return metricIt->second;
        }
    }
    return 0.0f;
}

void BlessedInfinityEngine::SetBlessedMetric(const std::string& blessedId, const std::string& metric, float value) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessedStructures.find(blessedId);
    if (it != s_blessedStructures.end()) {
        it->second.blessedMetrics[metric] = value;
    }
}

nlohmann::json BlessedInfinityEngine::GetBlessedInfinityMetrics() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    nlohmann::json metrics;
    
    metrics["blessedCount"] = static_cast<int>(s_blessedStructures.size());
    metrics["infinityCount"] = static_cast<int>(s_infinityBlesseds.size());
    metrics["abundantCount"] = static_cast<int>(s_abundantBlesseds.size());
    metrics["prosperousCount"] = static_cast<int>(s_prosperousBlesseds.size());
    metrics["graceCount"] = static_cast<int>(s_graceBlesseds.size());
    
    float totalBlessedness = 0.0f;
    int blessedBlesseds = 0;
    for (const auto& pair : s_blessedStructures) {
        totalBlessedness += pair.second.blessedness;
        if (pair.second.isBlessed) blessedBlesseds++;
    }
    metrics["totalBlessedness"] = totalBlessedness;
    metrics["averageBlessedness"] = s_blessedStructures.empty() ? 0.0f : totalBlessedness / s_blessedStructures.size();
    metrics["blessedBlesseds"] = blessedBlesseds;
    
    float totalInfinity = 0.0f;
    int infiniteBlesseds = 0;
    for (const auto& pair : s_infinityBlesseds) {
        totalInfinity += pair.second.infinity;
        if (pair.second.isInfinite) infiniteBlesseds++;
    }
    metrics["totalInfinity"] = totalInfinity;
    metrics["averageInfinity"] = s_infinityBlesseds.empty() ? 0.0f : totalInfinity / s_infinityBlesseds.size();
    metrics["infiniteBlesseds"] = infiniteBlesseds;
    
    float totalAbundance = 0.0f;
    int abundantBlesseds = 0;
    for (const auto& pair : s_abundantBlesseds) {
        totalAbundance += pair.second.abundance;
        if (pair.second.isAbundant) abundantBlesseds++;
    }
    metrics["totalAbundance"] = totalAbundance;
    metrics["averageAbundance"] = s_abundantBlesseds.empty() ? 0.0f : totalAbundance / s_abundantBlesseds.size();
    metrics["abundantBlesseds"] = abundantBlesseds;
    
    float totalProsperity = 0.0f;
    int prosperousBlesseds = 0;
    for (const auto& pair : s_prosperousBlesseds) {
        totalProsperity += pair.second.prosperity;
        if (pair.second.isProsperous) prosperousBlesseds++;
    }
    metrics["totalProsperity"] = totalProsperity;
    metrics["averageProsperity"] = s_prosperousBlesseds.empty() ? 0.0f : totalProsperity / s_prosperousBlesseds.size();
    metrics["prosperousBlesseds"] = prosperousBlesseds;
    
    float totalGrace = 0.0f;
    int gracedBlesseds = 0;
    for (const auto& pair : s_graceBlesseds) {
        totalGrace += pair.second.grace;
        if (pair.second.isGraced) gracedBlesseds++;
    }
    metrics["totalGrace"] = totalGrace;
    metrics["averageGrace"] = s_graceBlesseds.empty() ? 0.0f : totalGrace / s_graceBlesseds.size();
    metrics["gracedBlesseds"] = gracedBlesseds;
    
    metrics["tickCount"] = s_blessedTickCount;
    
    return metrics;
}

nlohmann::json BlessedInfinityEngine::GenerateBlessedInfinityReport() {
    nlohmann::json report;
    report["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    report["metrics"] = GetBlessedInfinityMetrics();
    
    auto structures = GetAllBlessedInfinityStructures();
    nlohmann::json structuresJson = nlohmann::json::array();
    for (const auto& structure : structures) {
        structuresJson.push_back(SerializeBlessedInfinityStructure(structure));
    }
    report["blessedStructures"] = structuresJson;
    
    auto infinities = GetAllInfinityBlesseds();
    nlohmann::json infinitiesJson = nlohmann::json::array();
    for (const auto& infinity : infinities) {
        infinitiesJson.push_back(SerializeInfinityBlessed(infinity));
    }
    report["infinityBlesseds"] = infinitiesJson;
    
    auto abundants = GetAllAbundantBlesseds();
    nlohmann::json abundantsJson = nlohmann::json::array();
    for (const auto& abundant : abundants) {
        abundantsJson.push_back(SerializeAbundantBlessed(abundant));
    }
    report["abundantBlesseds"] = abundantsJson;
    
    auto prosperouss = GetAllProsperousBlesseds();
    nlohmann::json prosperoussJson = nlohmann::json::array();
    for (const auto& prosperous : prosperouss) {
        prosperoussJson.push_back(SerializeProsperousBlessed(prosperous));
    }
    report["prosperousBlesseds"] = prosperoussJson;
    
    auto graces = GetAllGraceBlesseds();
    nlohmann::json gracesJson = nlohmann::json::array();
    for (const auto& grace : graces) {
        gracesJson.push_back(SerializeGraceBlessed(grace));
    }
    report["graceBlesseds"] = gracesJson;
    
    return report;
}

void BlessedInfinityEngine::ResetBlessedInfinityMetrics() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    s_blessedTickCount = 0;
}

nlohmann::json BlessedInfinityEngine::SerializeBlessedInfinityStructure(const BlessedInfinityStructure& structure) {
    nlohmann::json json;
    json["blessedId"] = structure.blessedId;
    json["name"] = structure.name;
    json["blessedness"] = structure.blessedness;
    json["infinity"] = structure.infinity;
    json["abundance"] = structure.abundance;
    json["prosperity"] = structure.prosperity;
    json["grace"] = structure.grace;
    json["isBlessed"] = structure.isBlessed;
    json["creationTime"] = structure.creationTime;
    json["lastBlessedUpdate"] = structure.lastBlessedUpdate;
    return json;
}

nlohmann::json BlessedInfinityEngine::SerializeInfinityBlessed(const InfinityBlessed& infinity) {
    nlohmann::json json;
    json["infinityId"] = infinity.infinityId;
    json["name"] = infinity.name;
    json["infinity"] = infinity.infinity;
    json["blessedness"] = infinity.blessedness;
    json["endlessness"] = infinity.endlessness;
    json["boundlessness"] = infinity.boundlessness;
    json["isInfinite"] = infinity.isInfinite;
    json["creationTime"] = infinity.creationTime;
    return json;
}

nlohmann::json BlessedInfinityEngine::SerializeAbundantBlessed(const AbundantBlessed& abundant) {
    nlohmann::json json;
    json["abundantId"] = abundant.abundantId;
    json["name"] = abundant.name;
    json["abundance"] = abundant.abundance;
    json["blessedness"] = abundant.blessedness;
    json["plenty"] = abundant.plenty;
    json["wealth"] = abundant.wealth;
    json["isAbundant"] = abundant.isAbundant;
    json["creationTime"] = abundant.creationTime;
    return json;
}

nlohmann::json BlessedInfinityEngine::SerializeProsperousBlessed(const ProsperousBlessed& prosperous) {
    nlohmann::json json;
    json["prosperousId"] = prosperous.prosperousId;
    json["name"] = prosperous.name;
    json["prosperity"] = prosperous.prosperity;
    json["blessedness"] = prosperous.blessedness;
    json["success"] = prosperous.success;
    json["flourishing"] = prosperous.flourishing;
    json["isProsperous"] = prosperous.isProsperous;
    json["creationTime"] = prosperous.creationTime;
    return json;
}

nlohmann::json BlessedInfinityEngine::SerializeGraceBlessed(const GraceBlessed& grace) {
    nlohmann::json json;
    json["graceId"] = grace.graceId;
    json["name"] = grace.name;
    json["grace"] = grace.grace;
    json["blessedness"] = grace.blessedness;
    json["mercy"] = grace.mercy;
    json["favor"] = grace.favor;
    json["isGraced"] = grace.isGraced;
    json["creationTime"] = grace.creationTime;
    return json;
}

} // namespace BlessedInfinity
