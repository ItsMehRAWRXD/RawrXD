#include "sacred/SacredDominionEngine.hpp"
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>

namespace SacredDominion {

std::atomic<bool> SacredDominionEngine::s_initialized(false);
std::atomic<int64_t> SacredDominionEngine::s_tickCount(0);
std::mutex SacredDominionEngine::s_structureMutex;
std::mutex SacredDominionEngine::s_dominionMutex;
std::mutex SacredDominionEngine::s_holyMutex;
std::mutex SacredDominionEngine::s_blessedMutex;
std::mutex SacredDominionEngine::s_sanctifiedMutex;
std::map<std::string, SacredStructure> SacredDominionEngine::s_structures;
std::map<std::string, DominionSacred> SacredDominionEngine::s_dominions;
std::map<std::string, HolySacred> SacredDominionEngine::s_holies;
std::map<std::string, BlessedSacred> SacredDominionEngine::s_blessed;
std::map<std::string, SanctifiedSacred> SacredDominionEngine::s_sanctified;

void SacredDominionEngine::Init() {
    if (s_initialized.exchange(true)) return;
    s_tickCount = 0;
}

void SacredDominionEngine::Shutdown() {
    if (!s_initialized.exchange(false)) return;
    std::lock_guard<std::mutex> lock1(s_structureMutex);
    std::lock_guard<std::mutex> lock2(s_dominionMutex);
    std::lock_guard<std::mutex> lock3(s_holyMutex);
    std::lock_guard<std::mutex> lock4(s_blessedMutex);
    std::lock_guard<std::mutex> lock5(s_sanctifiedMutex);
    s_structures.clear();
    s_dominions.clear();
    s_holies.clear();
    s_blessed.clear();
    s_sanctified.clear();
}

void SacredDominionEngine::OnTick() {
    s_tickCount++;
}

std::string SacredDominionEngine::CreateSacredStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    std::string id = GenerateSacredId();
    SacredStructure structure;
    structure.sacredId = id;
    structure.name = name;
    structure.sacredness = 0.1f;
    structure.dominion = 0.1f;
    structure.authority = 0.1f;
    structure.reverence = 0.1f;
    structure.sanctity = 0.1f;
    structure.isActive = true;
    structure.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure.lastModified = structure.createdAt;
    s_structures[id] = structure;
    return id;
}

bool SacredDominionEngine::DestroySacredStructure(const std::string& sacredId) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(sacredId);
    if (it != s_structures.end()) {
        s_structures.erase(it);
        return true;
    }
    return false;
}

SacredStructure* SacredDominionEngine::GetSacredStructure(const std::string& sacredId) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(sacredId);
    if (it != s_structures.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<SacredStructure> SacredDominionEngine::GetAllStructures() {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    std::vector<SacredStructure> result;
    for (auto& pair : s_structures) {
        result.push_back(pair.second);
    }
    return result;
}

void SacredDominionEngine::ExpandSacredness(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(sacredId);
    if (it != s_structures.end()) {
        it->second.sacredness = std::min(1.0f, it->second.sacredness + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void SacredDominionEngine::ExtendDominion(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(sacredId);
    if (it != s_structures.end()) {
        it->second.dominion = std::min(1.0f, it->second.dominion + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void SacredDominionEngine::IncreaseAuthority(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(sacredId);
    if (it != s_structures.end()) {
        it->second.authority = std::min(1.0f, it->second.authority + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void SacredDominionEngine::DeepenReverence(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(sacredId);
    if (it != s_structures.end()) {
        it->second.reverence = std::min(1.0f, it->second.reverence + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

void SacredDominionEngine::ElevateSanctity(const std::string& sacredId, float amount) {
    std::lock_guard<std::mutex> lock(s_structureMutex);
    auto it = s_structures.find(sacredId);
    if (it != s_structures.end()) {
        it->second.sanctity = std::min(1.0f, it->second.sanctity + amount);
        it->second.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
}

std::string SacredDominionEngine::EstablishDominionSacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    std::string id = GenerateDominionId();
    DominionSacred dominion;
    dominion.dominionId = id;
    dominion.name = name;
    dominion.dominion = 0.1f;
    dominion.sacredness = 0.1f;
    dominion.sovereignty = 0.1f;
    dominion.isDominion = false;
    dominion.establishedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominions[id] = dominion;
    return id;
}

bool SacredDominionEngine::DissolveDominionSacred(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        s_dominions.erase(it);
        return true;
    }
    return false;
}

DominionSacred* SacredDominionEngine::GetDominionSacred(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<DominionSacred> SacredDominionEngine::GetAllDominionSacreds() {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    std::vector<DominionSacred> result;
    for (auto& pair : s_dominions) {
        result.push_back(pair.second);
    }
    return result;
}

void SacredDominionEngine::ExpandDominion(const std::string& dominionId, float amount) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.dominion = std::min(1.0f, it->second.dominion + amount);
    }
}

void SacredDominionEngine::IncreaseSacredness(const std::string& dominionId, float amount) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.sacredness = std::min(1.0f, it->second.sacredness + amount);
    }
}

void SacredDominionEngine::AssertSovereignty(const std::string& dominionId, float amount) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.sovereignty = std::min(1.0f, it->second.sovereignty + amount);
    }
}

void SacredDominionEngine::DeclareDominion(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = s_dominions.find(dominionId);
    if (it != s_dominions.end()) {
        it->second.isDominion = true;
    }
}

std::string SacredDominionEngine::ManifestHolySacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    std::string id = GenerateHolyId();
    HolySacred holy;
    holy.holyId = id;
    holy.name = name;
    holy.holiness = 0.1f;
    holy.sacredness = 0.1f;
    holy.grace = 0.1f;
    holy.blessing = 0.1f;
    holy.isManifest = true;
    holy.manifestedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_holies[id] = holy;
    return id;
}

bool SacredDominionEngine::BanishHolySacred(const std::string& holyId) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto it = s_holies.find(holyId);
    if (it != s_holies.end()) {
        s_holies.erase(it);
        return true;
    }
    return false;
}

HolySacred* SacredDominionEngine::GetHolySacred(const std::string& holyId) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto it = s_holies.find(holyId);
    if (it != s_holies.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<HolySacred> SacredDominionEngine::GetAllHolySacreds() {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    std::vector<HolySacred> result;
    for (auto& pair : s_holies) {
        result.push_back(pair.second);
    }
    return result;
}

void SacredDominionEngine::ElevateHoliness(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto it = s_holies.find(holyId);
    if (it != s_holies.end()) {
        it->second.holiness = std::min(1.0f, it->second.holiness + amount);
    }
}

void SacredDominionEngine::ExpandSacrednessHoly(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto it = s_holies.find(holyId);
    if (it != s_holies.end()) {
        it->second.sacredness = std::min(1.0f, it->second.sacredness + amount);
    }
}

void SacredDominionEngine::BestowGrace(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto it = s_holies.find(holyId);
    if (it != s_holies.end()) {
        it->second.grace = std::min(1.0f, it->second.grace + amount);
    }
}

void SacredDominionEngine::GrantBlessing(const std::string& holyId, float amount) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto it = s_holies.find(holyId);
    if (it != s_holies.end()) {
        it->second.blessing = std::min(1.0f, it->second.blessing + amount);
    }
}

std::string SacredDominionEngine::RealizeBlessedSacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::string id = GenerateBlessedId();
    BlessedSacred blessed;
    blessed.blessedId = id;
    blessed.name = name;
    blessed.blessedness = 0.1f;
    blessed.sacredness = 0.1f;
    blessed.favor = 0.1f;
    blessed.isBlessed = false;
    blessed.realizedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_blessed[id] = blessed;
    return id;
}

bool SacredDominionEngine::ReleaseBlessedSacred(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        s_blessed.erase(it);
        return true;
    }
    return false;
}

BlessedSacred* SacredDominionEngine::GetBlessedSacred(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<BlessedSacred> SacredDominionEngine::GetAllBlessedSacreds() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<BlessedSacred> result;
    for (auto& pair : s_blessed) {
        result.push_back(pair.second);
    }
    return result;
}

void SacredDominionEngine::AmplifyBlessedness(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.blessedness = std::min(1.0f, it->second.blessedness + amount);
    }
}

void SacredDominionEngine::ExpandSacrednessBlessed(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.sacredness = std::min(1.0f, it->second.sacredness + amount);
    }
}

void SacredDominionEngine::IncreaseFavor(const std::string& blessedId, float amount) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.favor = std::min(1.0f, it->second.favor + amount);
    }
}

void SacredDominionEngine::DeclareBlessed(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = s_blessed.find(blessedId);
    if (it != s_blessed.end()) {
        it->second.isBlessed = true;
    }
}

std::string SacredDominionEngine::DiscoverSanctifiedSacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    std::string id = GenerateSanctifiedId();
    SanctifiedSacred sanctified;
    sanctified.sanctifiedId = id;
    sanctified.name = name;
    sanctified.sanctification = 0.1f;
    sanctified.sacredness = 0.1f;
    sanctified.consecration = 0.1f;
    sanctified.isSanctified = false;
    sanctified.discoveredAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sanctified[id] = sanctified;
    return id;
}

bool SacredDominionEngine::ConcealSanctifiedSacred(const std::string& sanctifiedId) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        s_sanctified.erase(it);
        return true;
    }
    return false;
}

SanctifiedSacred* SacredDominionEngine::GetSanctifiedSacred(const std::string& sanctifiedId) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<SanctifiedSacred> SacredDominionEngine::GetAllSanctifiedSacreds() {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    std::vector<SanctifiedSacred> result;
    for (auto& pair : s_sanctified) {
        result.push_back(pair.second);
    }
    return result;
}

void SacredDominionEngine::IncreaseSanctification(const std::string& sanctifiedId, float amount) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        it->second.sanctification = std::min(1.0f, it->second.sanctification + amount);
    }
}

void SacredDominionEngine::ExpandSacrednessSanctified(const std::string& sanctifiedId, float amount) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        it->second.sacredness = std::min(1.0f, it->second.sacredness + amount);
    }
}

void SacredDominionEngine::Consecrate(const std::string& sanctifiedId, float amount) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = s_sanctified.find(sanctifiedId);
    if (it != s_sanctified.end()) {
        it->second.consecration = std::min(1.0f, it->second.consecration + amount);
    }
}

nlohmann::json SacredDominionEngine::GetSacredMetrics() {
    nlohmann::json metrics;
    
    {
        std::lock_guard<std::mutex> lock(s_structureMutex);
        metrics["structureCount"] = s_structures.size();
        float totalSacredness = 0.0f;
        for (const auto& pair : s_structures) {
            totalSacredness += pair.second.sacredness;
        }
        metrics["totalSacredness"] = totalSacredness;
        metrics["averageSacredness"] = s_structures.empty() ? 0.0f : totalSacredness / s_structures.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        metrics["dominionCount"] = s_dominions.size();
        int dominionSacreds = 0;
        for (const auto& pair : s_dominions) {
            if (pair.second.isDominion) dominionSacreds++;
        }
        metrics["dominionSacreds"] = dominionSacreds;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_holyMutex);
        metrics["holyCount"] = s_holies.size();
        float totalHoliness = 0.0f;
        for (const auto& pair : s_holies) {
            totalHoliness += pair.second.holiness;
        }
        metrics["averageHoliness"] = s_holies.empty() ? 0.0f : totalHoliness / s_holies.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_blessedMutex);
        metrics["blessedCount"] = s_blessed.size();
        int blessedSacreds = 0;
        for (const auto& pair : s_blessed) {
            if (pair.second.isBlessed) blessedSacreds++;
        }
        metrics["blessedSacreds"] = blessedSacreds;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
        metrics["sanctifiedCount"] = s_sanctified.size();
        int sanctifiedSacreds = 0;
        for (const auto& pair : s_sanctified) {
            if (pair.second.isSanctified) sanctifiedSacreds++;
        }
        metrics["sanctifiedSacreds"] = sanctifiedSacreds;
    }
    
    metrics["tickCount"] = s_tickCount.load();
    return metrics;
}

nlohmann::json SacredDominionEngine::GenerateSacredReport() {
    nlohmann::json report;
    report["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    report["metrics"] = GetSacredMetrics();
    
    {
        std::lock_guard<std::mutex> lock(s_structureMutex);
        report["structures"] = nlohmann::json::array();
        for (const auto& pair : s_structures) {
            nlohmann::json structure;
            structure["sacredId"] = pair.second.sacredId;
            structure["name"] = pair.second.name;
            structure["sacredness"] = pair.second.sacredness;
            structure["dominion"] = pair.second.dominion;
            structure["authority"] = pair.second.authority;
            report["structures"].push_back(structure);
        }
    }
    
    return report;
}

int64_t SacredDominionEngine::GetTickCount() {
    return s_tickCount.load();
}

std::string SacredDominionEngine::GenerateSacredId() {
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

std::string SacredDominionEngine::GenerateDominionId() {
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

std::string SacredDominionEngine::GenerateHolyId() {
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

std::string SacredDominionEngine::GenerateBlessedId() {
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

std::string SacredDominionEngine::GenerateSanctifiedId() {
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

} // namespace SacredDominion
