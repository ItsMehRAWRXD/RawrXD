#include "holy/HolyDominionEngine.hpp"
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>

namespace Holy {

std::atomic<bool> HolyDominionEngine::s_initialized(false);
std::atomic<int64_t> HolyDominionEngine::s_tickCount(0);
std::mutex HolyDominionEngine::s_structureMutex;
std::mutex HolyDominionEngine::s_dominionMutex;
std::mutex HolyDominionEngine::s_sacredMutex;
std::mutex HolyDominionEngine::s_blessedMutex;
std::mutex HolyDominionEngine::s_sanctifiedMutex;
std::map<std::string, HolyStructure> HolyDominionEngine::s_structures;
std::map<std::string, DominionHoly> HolyDominionEngine::s_dominions;
std::map<std::string, SacredDominion> HolyDominionEngine::s_sacreds;
std::map<std::string, BlessedDominion> HolyDominionEngine::s_blessed;
std::map<std::string, SanctifiedDominion> HolyDominionEngine::s_sanctified;

void HolyDominionEngine::Init() {
    if (s_initialized.exchange(true)) return;
    s_tickCount = 0;
}

void HolyDominionEngine::Shutdown() {
    if (!s_initialized.exchange(false)) return;
    std::lock_guard<std::mutex> lock1(s_structureMutex);
    std::lock_guard<std::mutex> lock2(s_dominionMutex);
    std::lock_guard<std::mutex> lock3(s_sacredMutex);
    std::lock_guard<std::mutex> lock4(s_blessedMutex);
    std::lock_guard<std::mutex> lock5(s_sanctifiedMutex);
    s_structures.clear();
    s_dominions.clear();
    s_sacreds.clear();
    s_blessed.clear();
    s_sanctified.clear();
}

void HolyDominionEngine::OnTick() {
    s_tickCount++;
}

std::string HolyDominionEngine::CreateHolyStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    std::string id = GenerateHolyId();
    HolyStructure structure;
    structure.holyId = id;
    structure.name = name;
    structure.holiness = 0.1f;
    structure.dominion = 0.1f;
    structure.authority = 0.1f;
    structure.grace = 0.1f;
    structure.blessing = 0.1f;
    structure.isActive = true;
    structure.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure.lastModified = structure.createdAt;
    s_structures[id] = structure;
    return id;
}

bool HolyDominionEngine::DestroyHolyStructure(const std::string& holyId) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(holyId);
    if (it != s_structures.end()) {
        s_structures.erase(it);
        return true;
    }
    return false;
}

HolyStructure* HolyDominionEngine::GetHolyStructure(const std::string& holyId) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(holyId);
    if (it != s_structures.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<HolyStructure> HolyDominionEngine::GetAllStructures() {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    std::vector<HolyStructure> result;
    for (auto& pair : s_structures) {
        result.push_back(pair.second);
    }
    return result;
}

void HolyDominionEngine::ExpandHoliness(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(holyId);
    if (it != s_structures.end()) {
        it->second.holiness = std::min(1.0f, it->second.holiness + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void HolyDominionEngine::ExtendDominion(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(holyId);
    if (it != s_structures.end()) {
        it->second.dominion = std::min(1.0f, it->second.dominion + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void HolyDominionEngine::IncreaseAuthority(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(holyId);
    if (it != s_structures.end()) {
        it->second.authority = std::min(1.0f, it->second.authority + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void HolyDominionEngine::BestowGrace(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(holyId);
    if (it != s_structures.end()) {
        it->second.grace = std::min(1.0f, it->second.grace + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void HolyDominionEngine::GrantBlessing(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(holyId);
    if (it != s_structures.end()) {
        it->second.blessing = std::min(1.0f, it->second.blessing + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

std::string HolyDominionEngine::EstablishDominionHoly(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    std::string id = GenerateDominionId();
    DominionHoly dominion;
    dominion.dominionId = id;
    dominion.name = name;
    dominion.dominion = 0.1f;
    dominion.holiness = 0.1f;
    dominion.sovereignty = 0.1f;
    dominion.isDominion = false;
    dominion.establishedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominions[id] = dominion;
    return id;
}

bool HolyDominionEngine::DissolveDominionHoly(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        s_dominions.erase(it);
        return true;
    }
    return false;
}

DominionHoly* HolyDominionEngine::GetDominionHoly(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<DominionHoly> HolyDominionEngine::GetAllDominionHolies() {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    std::vector<DominionHoly> result;
    for (auto& pair : s_dominions) {
        result.push_back(pair.second);
    }
    return result;
}

void HolyDominionEngine::ExpandDominion(const std::string& dominionId, float amount) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.dominion = std::min(1.0f, it->second.dominion + amount);
    }
}

void HolyDominionEngine::IncreaseHoliness(const std::string& dominionId, float amount) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.holiness = std::min(1.0f, it->second.holiness + amount);
    }
}

void HolyDominionEngine::AssertSovereignty(const std::string& dominionId, float amount) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.sovereignty = std::min(1.0f, it->second.sovereignty + amount);
    }
}

void HolyDominionEngine::DeclareDominion(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.isDominion = true;
    }
}

std::string HolyDominionEngine::ManifestSacredDominion(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    std::string id = GenerateSacredId();
    SacredDominion sacred;
    sacred.sacredId = id;
    sacred.name = name;
    sacred.sacredness = 0.1f;
    sacred.dominion = 0.1f;
    sacred.reverence = 0.1f;
    sacred.sanctity = 0.1f;
    sacred.isManifest = true;
    sacred.manifestedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sacreds[id] = sacred;
    return id;
}

bool HolyDominionEngine::BanishSacredDominion(const std::string& sacredId) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto it = s_sacreds.find(sacredId);
    if (it != s_sacreds.end()) {
        s_sacreds.erase(it);
        return true;
    }
    return false;
}

SacredDominion* HolyDominionEngine::GetSacredDominion(const std::string& sacredId) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto it = s_sacreds.find(sacredId);
    if (it != s_sacreds.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<SacredDominion> HolyDominionEngine::GetAllSacredDominions() {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    std::vector<SacredDominion> result;
    for (auto& pair : s_sacreds) {
        result.push_back(pair.second);
    }
    return result;
}

void HolyDominionEngine::ElevateSacredness(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto it = s_sacreds.find(sacredId);
    if (it != s_sacreds.end()) {
        it->second.sacredness = std::min(1.0f, it->second.sacredness + amount);
    }
}

void HolyDominionEngine::ExpandDominionSacred(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto it = s_sacreds.find(sacredId);
    if (it != s_sacreds.end()) {
        it->second.dominion = std::min(1.0f, it->second.dominion + amount);
    }
}

void HolyDominionEngine::DeepenReverence(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto it = s_sacreds.find(sacredId);
    if (it != s_sacreds.end()) {
        it->second.reverence = std::min(1.0f, it->second.reverence + amount);
    }
}

void HolyDominionEngine::IncreaseSanctity(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto it = s_sacreds.find(sacredId);
    if (it != s_sacreds.end()) {
        it->second.sanctity = std::min(1.0f, it->second.sanctity + amount);
    }
}

std::string HolyDominionEngine::RealizeBlessedDominion(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::string id = GenerateBlessedId();
    BlessedDominion blessed;
    blessed.blessedId = id;
    blessed.name = name;
    blessed.blessedness = 0.1f;
    blessed.dominion = 0.1f;
    blessed.favor = 0.1f;
    blessed.isBlessed = false;
    blessed.realizedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessed[id] = blessed;
    return id;
}

bool HolyDominionEngine::ReleaseBlessedDominion(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        s_blessed.erase(it);
        return true;
    }
    return false;
}

BlessedDominion* HolyDominionEngine::GetBlessedDominion(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<BlessedDominion> HolyDominionEngine::GetAllBlessedDominions() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<BlessedDominion> result;
    for (auto& pair : s_blessed) {
        result.push_back(pair.second);
    }
    return result;
}

void HolyDominionEngine::AmplifyBlessedness(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.blessedness = std::min(1.0f, it->second.blessedness + amount);
    }
}

void HolyDominionEngine::ExtendDominion(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.dominion = std::min(1.0f, it->second.dominion + amount);
    }
}

void HolyDominionEngine::IncreaseFavor(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.favor = std::min(1.0f, it->second.favor + amount);
    }
}

void HolyDominionEngine::DeclareBlessed(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.isBlessed = true;
    }
}

std::string HolyDominionEngine::DiscoverSanctifiedDominion(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    std::string id = GenerateSanctifiedId();
    SanctifiedDominion sanctified;
    sanctified.sanctifiedId = id;
    sanctified.name = name;
    sanctified.sanctification = 0.1f;
    sanctified.dominion = 0.1f;
    sanctified.consecration = 0.1f;
    sanctified.isSanctified = false;
    sanctified.discoveredAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctified[id] = sanctified;
    return id;
}

bool HolyDominionEngine::ConcealSanctifiedDominion(const std::string& sanctifiedId) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        s_sanctified.erase(it);
        return true;
    }
    return false;
}

SanctifiedDominion* HolyDominionEngine::GetSanctifiedDominion(const std::string& sanctifiedId) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<SanctifiedDominion> HolyDominionEngine::GetAllSanctifiedDominions() {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    std::vector<SanctifiedDominion> result;
    for (auto& pair : s_sanctified) {
        result.push_back(pair.second);
    }
    return result;
}

void HolyDominionEngine::IncreaseSanctification(const std::string& sanctifiedId, float amount) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        it->second.sanctification = std::min(1.0f, it->second.sanctification + amount);
    }
}

void HolyDominionEngine::DeepenDominion(const std::string& sanctifiedId, float amount) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        it->second.dominion = std::min(1.0f, it->second.dominion + amount);
    }
}

void HolyDominionEngine::Consecrate(const std::string& sanctifiedId, float amount) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        it->second.consecration = std::min(1.0f, it->second.consecration + amount);
    }
}

nlohmann::json HolyDominionEngine::GetHolyMetrics() {
    nlohmann::json metrics;
    
    {
        std::lock_guard<std::mutex> lock(s_structureMutex);
        metrics["structureCount"] = s_structures.size();
        float totalHoliness = 0.0f;
        for (const auto& pair : s_structures) {
            totalHoliness += pair.second.holiness;
        }
        metrics["totalHoliness"] = totalHoliness;
        metrics["averageHoliness"] = s_structures.empty() ? 0.0f : totalHoliness / s_structures.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        metrics["dominionCount"] = s_dominions.size();
        int dominionHolies = 0;
        for (const auto& pair : s_dominions) {
            if (pair.second.isDominion) dominionHolies++;
        }
        metrics["dominionHolies"] = dominionHolies;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_sacredMutex);
        metrics["sacredCount"] = s_sacreds.size();
        float totalSacredness = 0.0f;
        for (const auto& pair : s_sacreds) {
            totalSacredness += pair.second.sacredness;
        }
        metrics["averageSacredness"] = s_sacreds.empty() ? 0.0f : totalSacredness / s_sacreds.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_blessedMutex);
        metrics["blessedCount"] = s_blessed.size();
        int blessedDominions = 0;
        for (const auto& pair : s_blessed) {
            if (pair.second.isBlessed) blessedDominions++;
        }
        metrics["blessedDominions"] = blessedDominions;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
        metrics["sanctifiedCount"] = s_sanctified.size();
        int sanctifiedDominions = 0;
        for (const auto& pair : s_sanctified) {
            if (pair.second.isSanctified) sanctifiedDominions++;
        }
        metrics["sanctifiedDominions"] = sanctifiedDominions;
    }
    
    metrics["tickCount"] = s_tickCount.load();
    return metrics;
}

nlohmann::json HolyDominionEngine::GenerateHolyReport() {
    nlohmann::json report;
    report["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    report["metrics"] = GetHolyMetrics();
    
    {
        std::lock_guard<std::mutex> lock(s_structureMutex);
        report["structures"] = nlohmann::json::array();
        for (const auto& pair : s_structures) {
            nlohmann::json structure;
            structure["holyId"] = pair.second.holyId;
            structure["name"] = pair.second.name;
            structure["holiness"] = pair.second.holiness;
            structure["dominion"] = pair.second.dominion;
            structure["authority"] = pair.second.authority;
            report["structures"].push_back(structure);
        }
    }
    
    return report;
}

int64_t HolyDominionEngine::GetTickCount() {
    return s_tickCount.load();
}

std::string HolyDominionEngine::GenerateHolyId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static const char* hex = "0123456789abcdef";
    
    std::stringstream ss;
    ss << "holy_";
    for (int i = 0; i < 16; i++) {
        ss << hex[dis(gen)];
    }
    return ss.str();
}

std::string HolyDominionEngine::GenerateDominionId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static const char* hex = "0123456789abcdef";
    
    std::stringstream ss;
    ss << "dominion_";
    for (int i = 0; i < 16; i++) {
        ss << hex[dis(gen)];
    }
    return ss.str();
}

std::string HolyDominionEngine::GenerateSacredId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static const char* hex = "0123456789abcdef";
    
    std::stringstream ss;
    ss << "sacred_";
    for (int i = 0; i < 16; i++) {
        ss << hex[dis(gen)];
    }
    return ss.str();
}

std::string HolyDominionEngine::GenerateBlessedId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static const char* hex = "0123456789abcdef";
    
    std::stringstream ss;
    ss << "blessed_";
    for (int i = 0; i < 16; i++) {
        ss << hex[dis(gen)];
    }
    return ss.str();
}

std::string HolyDominionEngine::GenerateSanctifiedId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static const char* hex = "0123456789abcdef";
    
    std::stringstream ss;
    ss << "sanctified_";
    for (int i = 0; i < 16; i++) {
        ss << hex[dis(gen)];
    }
    return ss.str();
}

} // namespace Holy
