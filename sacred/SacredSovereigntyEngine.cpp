#include "sacred/SacredSovereigntyEngine.hpp"
#include <chrono>
#include <algorithm>

namespace SacredSovereignty {

// Static member definitions
bool SacredSovereigntyEngine::s_initialized = false;
std::mutex SacredSovereigntyEngine::s_sacredMutex;
std::mutex SacredSovereigntyEngine::s_sovereigntyMutex;
std::mutex SacredSovereigntyEngine::s_authorityMutex;
std::mutex SacredSovereigntyEngine::s_dominionMutex;
std::mutex SacredSovereigntyEngine::s_supremacyMutex;

std::vector<std::shared_ptr<SacredSovereigntyStructure>> SacredSovereigntyEngine::s_sacredStructures;
std::vector<std::shared_ptr<SovereigntySacred>> SacredSovereigntyEngine::s_sovereigntySacreds;
std::vector<std::shared_ptr<AuthoritySacred>> SacredSovereigntyEngine::s_authoritySacreds;
std::vector<std::shared_ptr<DominionSacred>> SacredSovereigntyEngine::s_dominionSacreds;
std::vector<std::shared_ptr<SupremacySacred>> SacredSovereigntyEngine::s_supremacySacreds;

std::atomic<int64_t> SacredSovereigntyEngine::s_sacredCounter(0);
std::atomic<int64_t> SacredSovereigntyEngine::s_sovereigntyCounter(0);
std::atomic<int64_t> SacredSovereigntyEngine::s_authorityCounter(0);
std::atomic<int64_t> SacredSovereigntyEngine::s_dominionCounter(0);
std::atomic<int64_t> SacredSovereigntyEngine::s_supremacyCounter(0);

// JSON serialization implementations
nlohmann::json SacredSovereigntyStructure::ToJson() const {
    nlohmann::json j;
    j["sacredId"] = sacredId;
    j["name"] = name;
    j["sacredness"] = sacredness;
    j["sovereignty"] = sovereignty;
    j["authority"] = authority;
    j["dominion"] = dominion;
    j["supremacy"] = supremacy;
    j["createdAt"] = createdAt;
    j["lastModified"] = lastModified;
    j["isActive"] = isActive;
    return j;
}

SacredSovereigntyStructure SacredSovereigntyStructure::FromJson(const nlohmann::json& j) {
    SacredSovereigntyStructure s;
    s.sacredId = j.value("sacredId", "");
    s.name = j.value("name", "");
    s.sacredness = j.value("sacredness", 0.0f);
    s.sovereignty = j.value("sovereignty", 0.0f);
    s.authority = j.value("authority", 0.0f);
    s.dominion = j.value("dominion", 0.0f);
    s.supremacy = j.value("supremacy", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json SovereigntySacred::ToJson() const {
    nlohmann::json j;
    j["sovereigntyId"] = sovereigntyId;
    j["name"] = name;
    j["sovereignty"] = sovereignty;
    j["sacredness"] = sacredness;
    j["rule"] = rule;
    j["reign"] = reign;
    j["isAbsolute"] = isAbsolute;
    j["createdAt"] = createdAt;
    return j;
}

SovereigntySacred SovereigntySacred::FromJson(const nlohmann::json& j) {
    SovereigntySacred s;
    s.sovereigntyId = j.value("sovereigntyId", "");
    s.name = j.value("name", "");
    s.sovereignty = j.value("sovereignty", 0.0f);
    s.sacredness = j.value("sacredness", 0.0f);
    s.rule = j.value("rule", 0.0f);
    s.reign = j.value("reign", 0.0f);
    s.isAbsolute = j.value("isAbsolute", false);
    s.createdAt = j.value("createdAt", 0);
    return s;
}

nlohmann::json AuthoritySacred::ToJson() const {
    nlohmann::json j;
    j["authorityId"] = authorityId;
    j["name"] = name;
    j["authority"] = authority;
    j["sacredness"] = sacredness;
    j["command"] = command;
    j["control"] = control;
    j["createdAt"] = createdAt;
    return j;
}

AuthoritySacred AuthoritySacred::FromJson(const nlohmann::json& j) {
    AuthoritySacred a;
    a.authorityId = j.value("authorityId", "");
    a.name = j.value("name", "");
    a.authority = j.value("authority", 0.0f);
    a.sacredness = j.value("sacredness", 0.0f);
    a.command = j.value("command", 0.0f);
    a.control = j.value("control", 0.0f);
    a.createdAt = j.value("createdAt", 0);
    return a;
}

nlohmann::json DominionSacred::ToJson() const {
    nlohmann::json j;
    j["dominionId"] = dominionId;
    j["name"] = name;
    j["dominion"] = dominion;
    j["sacredness"] = sacredness;
    j["territory"] = territory;
    j["realm"] = realm;
    j["isVast"] = isVast;
    j["createdAt"] = createdAt;
    return j;
}

DominionSacred DominionSacred::FromJson(const nlohmann::json& j) {
    DominionSacred d;
    d.dominionId = j.value("dominionId", "");
    d.name = j.value("name", "");
    d.dominion = j.value("dominion", 0.0f);
    d.sacredness = j.value("sacredness", 0.0f);
    d.territory = j.value("territory", 0.0f);
    d.realm = j.value("realm", 0.0f);
    d.isVast = j.value("isVast", false);
    d.createdAt = j.value("createdAt", 0);
    return d;
}

nlohmann::json SupremacySacred::ToJson() const {
    nlohmann::json j;
    j["supremacyId"] = supremacyId;
    j["name"] = name;
    j["supremacy"] = supremacy;
    j["sacredness"] = sacredness;
    j["dominance"] = dominance;
    j["preeminence"] = preeminence;
    j["createdAt"] = createdAt;
    return j;
}

SupremacySacred SupremacySacred::FromJson(const nlohmann::json& j) {
    SupremacySacred s;
    s.supremacyId = j.value("supremacyId", "");
    s.name = j.value("name", "");
    s.supremacy = j.value("supremacy", 0.0f);
    s.sacredness = j.value("sacredness", 0.0f);
    s.dominance = j.value("dominance", 0.0f);
    s.preeminence = j.value("preeminence", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    return s;
}

// Engine implementation
void SacredSovereigntyEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void SacredSovereigntyEngine::Shutdown() {
    if (!s_initialized) return;
    {
        std::lock_guard<std::mutex> lock(s_sacredMutex);
        s_sacredStructures.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
        s_sovereigntySacreds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_authorityMutex);
        s_authoritySacreds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        s_dominionSacreds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_supremacyMutex);
        s_supremacySacreds.clear();
    }
    s_initialized = false;
}

bool SacredSovereigntyEngine::IsInitialized() {
    return s_initialized;
}

// Sacred Sovereignty Structure operations
std::string SacredSovereigntyEngine::CreateSacredSovereigntyStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto structure = std::make_shared<SacredSovereigntyStructure>();
    structure->sacredId = "sacred_" + std::to_string(++s_sacredCounter);
    structure->name = name;
    structure->sacredness = 0.1f;
    structure->sovereignty = 0.1f;
    structure->authority = 0.1f;
    structure->dominion = 0.1f;
    structure->supremacy = 0.1f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    s_sacredStructures.push_back(structure);
    return structure->sacredId;
}

bool SacredSovereigntyEngine::DestroySacredSovereigntyStructure(const std::string& sacredId) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    auto it = std::remove_if(s_sacredStructures.begin(), s_sacredStructures.end(),
        [&sacredId](const auto& s) { return s->sacredId == sacredId; });
    if (it != s_sacredStructures.end()) {
        s_sacredStructures.erase(it, s_sacredStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<SacredSovereigntyStructure> SacredSovereigntyEngine::GetSacredSovereigntyStructure(const std::string& sacredId) {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    for (auto& s : s_sacredStructures) {
        if (s->sacredId == sacredId) return s;
    }
    return nullptr;
}

std::vector<SacredSovereigntyStructure> SacredSovereigntyEngine::GetAllSacredSovereigntyStructures() {
    std::lock_guard<std::mutex> lock(s_sacredMutex);
    std::vector<SacredSovereigntyStructure> result;
    for (auto& s : s_sacredStructures) {
        result.push_back(*s);
    }
    return result;
}

bool SacredSovereigntyEngine::ElevateSacredness(const std::string& sacredId, float amount) {
    auto s = GetSacredSovereigntyStructure(sacredId);
    if (!s) return false;
    s->sacredness = std::min(1.0f, s->sacredness + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SacredSovereigntyEngine::ExpandSovereignty(const std::string& sacredId, float amount) {
    auto s = GetSacredSovereigntyStructure(sacredId);
    if (!s) return false;
    s->sovereignty = std::min(1.0f, s->sovereignty + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SacredSovereigntyEngine::AssertAuthority(const std::string& sacredId, float amount) {
    auto s = GetSacredSovereigntyStructure(sacredId);
    if (!s) return false;
    s->authority = std::min(1.0f, s->authority + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SacredSovereigntyEngine::ExtendDominion(const std::string& sacredId, float amount) {
    auto s = GetSacredSovereigntyStructure(sacredId);
    if (!s) return false;
    s->dominion = std::min(1.0f, s->dominion + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SacredSovereigntyEngine::AchieveSupremacy(const std::string& sacredId, float amount) {
    auto s = GetSacredSovereigntyStructure(sacredId);
    if (!s) return false;
    s->supremacy = std::min(1.0f, s->supremacy + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

// Sovereignty Sacred operations
std::string SacredSovereigntyEngine::CreateSovereigntySacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    auto sovereignty = std::make_shared<SovereigntySacred>();
    sovereignty->sovereigntyId = "sovereignty_" + std::to_string(++s_sovereigntyCounter);
    sovereignty->name = name;
    sovereignty->sovereignty = 0.1f;
    sovereignty->sacredness = 0.1f;
    sovereignty->rule = 0.1f;
    sovereignty->reign = 0.1f;
    sovereignty->isAbsolute = false;
    sovereignty->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sovereigntySacreds.push_back(sovereignty);
    return sovereignty->sovereigntyId;
}

bool SacredSovereigntyEngine::DestroySovereigntySacred(const std::string& sovereigntyId) {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    auto it = std::remove_if(s_sovereigntySacreds.begin(), s_sovereigntySacreds.end(),
        [&sovereigntyId](const auto& s) { return s->sovereigntyId == sovereigntyId; });
    if (it != s_sovereigntySacreds.end()) {
        s_sovereigntySacreds.erase(it, s_sovereigntySacreds.end());
        return true;
    }
    return false;
}

std::shared_ptr<SovereigntySacred> SacredSovereigntyEngine::GetSovereigntySacred(const std::string& sovereigntyId) {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    for (auto& s : s_sovereigntySacreds) {
        if (s->sovereigntyId == sovereigntyId) return s;
    }
    return nullptr;
}

std::vector<SovereigntySacred> SacredSovereigntyEngine::GetAllSovereigntySacreds() {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    std::vector<SovereigntySacred> result;
    for (auto& s : s_sovereigntySacreds) {
        result.push_back(*s);
    }
    return result;
}

bool SacredSovereigntyEngine::EstablishRule(const std::string& sovereigntyId, float amount) {
    auto s = GetSovereigntySacred(sovereigntyId);
    if (!s) return false;
    s->rule = std::min(1.0f, s->rule + amount);
    return true;
}

bool SacredSovereigntyEngine::ExtendReign(const std::string& sovereigntyId, float amount) {
    auto s = GetSovereigntySacred(sovereigntyId);
    if (!s) return false;
    s->reign = std::min(1.0f, s->reign + amount);
    return true;
}

bool SacredSovereigntyEngine::DeclareAbsolute(const std::string& sovereigntyId) {
    auto s = GetSovereigntySacred(sovereigntyId);
    if (!s) return false;
    s->isAbsolute = true;
    return true;
}

// Authority Sacred operations
std::string SacredSovereigntyEngine::CreateAuthoritySacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_authorityMutex);
    auto authority = std::make_shared<AuthoritySacred>();
    authority->authorityId = "authority_" + std::to_string(++s_authorityCounter);
    authority->name = name;
    authority->authority = 0.1f;
    authority->sacredness = 0.1f;
    authority->command = 0.1f;
    authority->control = 0.1f;
    authority->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_authoritySacreds.push_back(authority);
    return authority->authorityId;
}

bool SacredSovereigntyEngine::DestroyAuthoritySacred(const std::string& authorityId) {
    std::lock_guard<std::mutex> lock(s_authorityMutex);
    auto it = std::remove_if(s_authoritySacreds.begin(), s_authoritySacreds.end(),
        [&authorityId](const auto& a) { return a->authorityId == authorityId; });
    if (it != s_authoritySacreds.end()) {
        s_authoritySacreds.erase(it, s_authoritySacreds.end());
        return true;
    }
    return false;
}

std::shared_ptr<AuthoritySacred> SacredSovereigntyEngine::GetAuthoritySacred(const std::string& authorityId) {
    std::lock_guard<std::mutex> lock(s_authorityMutex);
    for (auto& a : s_authoritySacreds) {
        if (a->authorityId == authorityId) return a;
    }
    return nullptr;
}

std::vector<AuthoritySacred> SacredSovereigntyEngine::GetAllAuthoritySacreds() {
    std::lock_guard<std::mutex> lock(s_authorityMutex);
    std::vector<AuthoritySacred> result;
    for (auto& a : s_authoritySacreds) {
        result.push_back(*a);
    }
    return result;
}

bool SacredSovereigntyEngine::IssueCommand(const std::string& authorityId, float amount) {
    auto a = GetAuthoritySacred(authorityId);
    if (!a) return false;
    a->command = std::min(1.0f, a->command + amount);
    return true;
}

bool SacredSovereigntyEngine::SeizeControl(const std::string& authorityId, float amount) {
    auto a = GetAuthoritySacred(authorityId);
    if (!a) return false;
    a->control = std::min(1.0f, a->control + amount);
    return true;
}

// Dominion Sacred operations
std::string SacredSovereigntyEngine::CreateDominionSacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto dominion = std::make_shared<DominionSacred>();
    dominion->dominionId = "dominion_" + std::to_string(++s_dominionCounter);
    dominion->name = name;
    dominion->dominion = 0.1f;
    dominion->sacredness = 0.1f;
    dominion->territory = 0.1f;
    dominion->realm = 0.1f;
    dominion->isVast = false;
    dominion->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionSacreds.push_back(dominion);
    return dominion->dominionId;
}

bool SacredSovereigntyEngine::DestroyDominionSacred(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = std::remove_if(s_dominionSacreds.begin(), s_dominionSacreds.end(),
        [&dominionId](const auto& d) { return d->dominionId == dominionId; });
    if (it != s_dominionSacreds.end()) {
        s_dominionSacreds.erase(it, s_dominionSacreds.end());
        return true;
    }
    return false;
}

std::shared_ptr<DominionSacred> SacredSovereigntyEngine::GetDominionSacred(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    for (auto& d : s_dominionSacreds) {
        if (d->dominionId == dominionId) return d;
    }
    return nullptr;
}

std::vector<DominionSacred> SacredSovereigntyEngine::GetAllDominionSacreds() {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    std::vector<DominionSacred> result;
    for (auto& d : s_dominionSacreds) {
        result.push_back(*d);
    }
    return result;
}

bool SacredSovereigntyEngine::ExpandTerritory(const std::string& dominionId, float amount) {
    auto d = GetDominionSacred(dominionId);
    if (!d) return false;
    d->territory = std::min(1.0f, d->territory + amount);
    return true;
}

bool SacredSovereigntyEngine::ClaimRealm(const std::string& dominionId, float amount) {
    auto d = GetDominionSacred(dominionId);
    if (!d) return false;
    d->realm = std::min(1.0f, d->realm + amount);
    return true;
}

bool SacredSovereigntyEngine::DeclareVast(const std::string& dominionId) {
    auto d = GetDominionSacred(dominionId);
    if (!d) return false;
    d->isVast = true;
    return true;
}

// Supremacy Sacred operations
std::string SacredSovereigntyEngine::CreateSupremacySacred(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_supremacyMutex);
    auto supremacy = std::make_shared<SupremacySacred>();
    supremacy->supremacyId = "supremacy_" + std::to_string(++s_supremacyCounter);
    supremacy->name = name;
    supremacy->supremacy = 0.1f;
    supremacy->sacredness = 0.1f;
    supremacy->dominance = 0.1f;
    supremacy->preeminence = 0.1f;
    supremacy->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_supremacySacreds.push_back(supremacy);
    return supremacy->supremacyId;
}

bool SacredSovereigntyEngine::DestroySupremacySacred(const std::string& supremacyId) {
    std::lock_guard<std::mutex> lock(s_supremacyMutex);
    auto it = std::remove_if(s_supremacySacreds.begin(), s_supremacySacreds.end(),
        [&supremacyId](const auto& s) { return s->supremacyId == supremacyId; });
    if (it != s_supremacySacreds.end()) {
        s_supremacySacreds.erase(it, s_supremacySacreds.end());
        return true;
    }
    return false;
}

std::shared_ptr<SupremacySacred> SacredSovereigntyEngine::GetSupremacySacred(const std::string& supremacyId) {
    std::lock_guard<std::mutex> lock(s_supremacyMutex);
    for (auto& s : s_supremacySacreds) {
        if (s->supremacyId == supremacyId) return s;
    }
    return nullptr;
}

std::vector<SupremacySacred> SacredSovereigntyEngine::GetAllSupremacySacreds() {
    std::lock_guard<std::mutex> lock(s_supremacyMutex);
    std::vector<SupremacySacred> result;
    for (auto& s : s_supremacySacreds) {
        result.push_back(*s);
    }
    return result;
}

bool SacredSovereigntyEngine::AssertDominance(const std::string& supremacyId, float amount) {
    auto s = GetSupremacySacred(supremacyId);
    if (!s) return false;
    s->dominance = std::min(1.0f, s->dominance + amount);
    return true;
}

bool SacredSovereigntyEngine::EstablishPreeminence(const std::string& supremacyId, float amount) {
    auto s = GetSupremacySacred(supremacyId);
    if (!s) return false;
    s->preeminence = std::min(1.0f, s->preeminence + amount);
    return true;
}

// Metrics and reporting
nlohmann::json SacredSovereigntyEngine::GetSacredSovereigntyMetrics() {
    nlohmann::json metrics;
    
    {
        std::lock_guard<std::mutex> lock(s_sacredMutex);
        metrics["sacredCount"] = s_sacredStructures.size();
        float totalSacredness = 0.0f;
        int sacredSacreds = 0;
        for (auto& s : s_sacredStructures) {
            totalSacredness += s->sacredness;
            if (s->sacredness > 0.7f) sacredSacreds++;
        }
        metrics["totalSacredness"] = totalSacredness;
        metrics["averageSacredness"] = s_sacredStructures.empty() ? 0.0f : totalSacredness / s_sacredStructures.size();
        metrics["sacredSacreds"] = sacredSacreds;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
        metrics["sovereigntyCount"] = s_sovereigntySacreds.size();
        float totalSovereignty = 0.0f;
        int absoluteSovereignties = 0;
        for (auto& s : s_sovereigntySacreds) {
            totalSovereignty += s->sovereignty;
            if (s->isAbsolute) absoluteSovereignties++;
        }
        metrics["totalSovereignty"] = totalSovereignty;
        metrics["absoluteSovereignties"] = absoluteSovereignties;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_authorityMutex);
        metrics["authorityCount"] = s_authoritySacreds.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        metrics["dominionCount"] = s_dominionSacreds.size();
        int vastDominions = 0;
        for (auto& d : s_dominionSacreds) {
            if (d->isVast) vastDominions++;
        }
        metrics["vastDominions"] = vastDominions;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_supremacyMutex);
        metrics["supremacyCount"] = s_supremacySacreds.size();
    }
    
    return metrics;
}

nlohmann::json SacredSovereigntyEngine::GenerateSacredSovereigntyReport() {
    nlohmann::json report;
    report["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    report["metrics"] = GetSacredSovereigntyMetrics();
    
    {
        std::lock_guard<std::mutex> lock(s_sacredMutex);
        nlohmann::json structures = nlohmann::json::array();
        for (auto& s : s_sacredStructures) {
            structures.push_back(s->ToJson());
        }
        report["sacredStructures"] = structures;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
        nlohmann::json sovereignties = nlohmann::json::array();
        for (auto& s : s_sovereigntySacreds) {
            sovereignties.push_back(s->ToJson());
        }
        report["sovereigntySacreds"] = sovereignties;
    }
    
    return report;
}

} // namespace SacredSovereignty
