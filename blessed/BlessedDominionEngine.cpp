#include "blessed/BlessedDominionEngine.hpp"
#include <chrono>
#include <algorithm>

namespace BlessedDominion {

// Static member definitions
bool BlessedDominionEngine::s_initialized = false;
std::mutex BlessedDominionEngine::s_blessedMutex;
std::mutex BlessedDominionEngine::s_dominionMutex;
std::mutex BlessedDominionEngine::s_graceMutex;
std::mutex BlessedDominionEngine::s_favorMutex;
std::mutex BlessedDominionEngine::s_providenceMutex;

std::vector<std::shared_ptr<BlessedDominionStructure>> BlessedDominionEngine::s_blessedStructures;
std::vector<std::shared_ptr<DominionBlessed>> BlessedDominionEngine::s_dominionBlesseds;
std::vector<std::shared_ptr<GraceBlessed>> BlessedDominionEngine::s_graceBlesseds;
std::vector<std::shared_ptr<FavorBlessed>> BlessedDominionEngine::s_favorBlesseds;
std::vector<std::shared_ptr<ProvidenceBlessed>> BlessedDominionEngine::s_providenceBlesseds;

std::atomic<int64_t> BlessedDominionEngine::s_blessedCounter(0);
std::atomic<int64_t> BlessedDominionEngine::s_dominionCounter(0);
std::atomic<int64_t> BlessedDominionEngine::s_graceCounter(0);
std::atomic<int64_t> BlessedDominionEngine::s_favorCounter(0);
std::atomic<int64_t> BlessedDominionEngine::s_providenceCounter(0);

// JSON serialization implementations
nlohmann::json BlessedDominionStructure::ToJson() const {
    nlohmann::json j;
    j["blessedId"] = blessedId;
    j["name"] = name;
    j["blessedness"] = blessedness;
    j["dominion"] = dominion;
    j["grace"] = grace;
    j["favor"] = favor;
    j["providence"] = providence;
    j["createdAt"] = createdAt;
    j["lastModified"] = lastModified;
    j["isActive"] = isActive;
    return j;
}

BlessedDominionStructure BlessedDominionStructure::FromJson(const nlohmann::json& j) {
    BlessedDominionStructure s;
    s.blessedId = j.value("blessedId", "");
    s.name = j.value("name", "");
    s.blessedness = j.value("blessedness", 0.0f);
    s.dominion = j.value("dominion", 0.0f);
    s.grace = j.value("grace", 0.0f);
    s.favor = j.value("favor", 0.0f);
    s.providence = j.value("providence", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json DominionBlessed::ToJson() const {
    nlohmann::json j;
    j["dominionId"] = dominionId;
    j["name"] = name;
    j["dominion"] = dominion;
    j["blessedness"] = blessedness;
    j["authority"] = authority;
    j["sovereignty"] = sovereignty;
    j["isSovereign"] = isSovereign;
    j["createdAt"] = createdAt;
    return j;
}

DominionBlessed DominionBlessed::FromJson(const nlohmann::json& j) {
    DominionBlessed d;
    d.dominionId = j.value("dominionId", "");
    d.name = j.value("name", "");
    d.dominion = j.value("dominion", 0.0f);
    d.blessedness = j.value("blessedness", 0.0f);
    d.authority = j.value("authority", 0.0f);
    d.sovereignty = j.value("sovereignty", 0.0f);
    d.isSovereign = j.value("isSovereign", false);
    d.createdAt = j.value("createdAt", 0);
    return d;
}

nlohmann::json GraceBlessed::ToJson() const {
    nlohmann::json j;
    j["graceId"] = graceId;
    j["name"] = name;
    j["grace"] = grace;
    j["blessedness"] = blessedness;
    j["mercy"] = mercy;
    j["kindness"] = kindness;
    j["createdAt"] = createdAt;
    return j;
}

GraceBlessed GraceBlessed::FromJson(const nlohmann::json& j) {
    GraceBlessed g;
    g.graceId = j.value("graceId", "");
    g.name = j.value("name", "");
    g.grace = j.value("grace", 0.0f);
    g.blessedness = j.value("blessedness", 0.0f);
    g.mercy = j.value("mercy", 0.0f);
    g.kindness = j.value("kindness", 0.0f);
    g.createdAt = j.value("createdAt", 0);
    return g;
}

nlohmann::json FavorBlessed::ToJson() const {
    nlohmann::json j;
    j["favorId"] = favorId;
    j["name"] = name;
    j["favor"] = favor;
    j["blessedness"] = blessedness;
    j["preference"] = preference;
    j["approval"] = approval;
    j["isPreferred"] = isPreferred;
    j["createdAt"] = createdAt;
    return j;
}

FavorBlessed FavorBlessed::FromJson(const nlohmann::json& j) {
    FavorBlessed f;
    f.favorId = j.value("favorId", "");
    f.name = j.value("name", "");
    f.favor = j.value("favor", 0.0f);
    f.blessedness = j.value("blessedness", 0.0f);
    f.preference = j.value("preference", 0.0f);
    f.approval = j.value("approval", 0.0f);
    f.isPreferred = j.value("isPreferred", false);
    f.createdAt = j.value("createdAt", 0);
    return f;
}

nlohmann::json ProvidenceBlessed::ToJson() const {
    nlohmann::json j;
    j["providenceId"] = providenceId;
    j["name"] = name;
    j["providence"] = providence;
    j["blessedness"] = blessedness;
    j["guidance"] = guidance;
    j["protection"] = protection;
    j["createdAt"] = createdAt;
    return j;
}

ProvidenceBlessed ProvidenceBlessed::FromJson(const nlohmann::json& j) {
    ProvidenceBlessed p;
    p.providenceId = j.value("providenceId", "");
    p.name = j.value("name", "");
    p.providence = j.value("providence", 0.0f);
    p.blessedness = j.value("blessedness", 0.0f);
    p.guidance = j.value("guidance", 0.0f);
    p.protection = j.value("protection", 0.0f);
    p.createdAt = j.value("createdAt", 0);
    return p;
}

// Engine implementation
void BlessedDominionEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void BlessedDominionEngine::Shutdown() {
    if (!s_initialized) return;
    {
        std::lock_guard<std::mutex> lock(s_blessedMutex);
        s_blessedStructures.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        s_dominionBlesseds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_graceMutex);
        s_graceBlesseds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_favorMutex);
        s_favorBlesseds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_providenceMutex);
        s_providenceBlesseds.clear();
    }
    s_initialized = false;
}

bool BlessedDominionEngine::IsInitialized() {
    return s_initialized;
}

// Blessed Dominion Structure operations
std::string BlessedDominionEngine::CreateBlessedDominionStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto structure = std::make_shared<BlessedDominionStructure>();
    structure->blessedId = "blessed_" + std::to_string(++s_blessedCounter);
    structure->name = name;
    structure->blessedness = 0.1f;
    structure->dominion = 0.1f;
    structure->grace = 0.1f;
    structure->favor = 0.1f;
    structure->providence = 0.1f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    s_blessedStructures.push_back(structure);
    return structure->blessedId;
}

bool BlessedDominionEngine::DestroyBlessedDominionStructure(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    auto it = std::remove_if(s_blessedStructures.begin(), s_blessedStructures.end(),
        [&blessedId](const auto& s) { return s->blessedId == blessedId; });
    if (it != s_blessedStructures.end()) {
        s_blessedStructures.erase(it, s_blessedStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<BlessedDominionStructure> BlessedDominionEngine::GetBlessedDominionStructure(const std::string& blessedId) {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    for (auto& s : s_blessedStructures) {
        if (s->blessedId == blessedId) return s;
    }
    return nullptr;
}

std::vector<BlessedDominionStructure> BlessedDominionEngine::GetAllBlessedDominionStructures() {
    std::lock_guard<std::mutex> lock(s_blessedMutex);
    std::vector<BlessedDominionStructure> result;
    for (auto& s : s_blessedStructures) {
        result.push_back(*s);
    }
    return result;
}

bool BlessedDominionEngine::ElevateBlessedness(const std::string& blessedId, float amount) {
    auto s = GetBlessedDominionStructure(blessedId);
    if (!s) return false;
    s->blessedness = std::min(1.0f, s->blessedness + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool BlessedDominionEngine::ExpandDominion(const std::string& blessedId, float amount) {
    auto s = GetBlessedDominionStructure(blessedId);
    if (!s) return false;
    s->dominion = std::min(1.0f, s->dominion + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool BlessedDominionEngine::BestowGrace(const std::string& blessedId, float amount) {
    auto s = GetBlessedDominionStructure(blessedId);
    if (!s) return false;
    s->grace = std::min(1.0f, s->grace + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool BlessedDominionEngine::GrantFavor(const std::string& blessedId, float amount) {
    auto s = GetBlessedDominionStructure(blessedId);
    if (!s) return false;
    s->favor = std::min(1.0f, s->favor + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool BlessedDominionEngine::ProvideProvidence(const std::string& blessedId, float amount) {
    auto s = GetBlessedDominionStructure(blessedId);
    if (!s) return false;
    s->providence = std::min(1.0f, s->providence + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

// Dominion Blessed operations
std::string BlessedDominionEngine::CreateDominionBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto dominion = std::make_shared<DominionBlessed>();
    dominion->dominionId = "dominion_" + std::to_string(++s_dominionCounter);
    dominion->name = name;
    dominion->dominion = 0.1f;
    dominion->blessedness = 0.1f;
    dominion->authority = 0.1f;
    dominion->sovereignty = 0.1f;
    dominion->isSovereign = false;
    dominion->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionBlesseds.push_back(dominion);
    return dominion->dominionId;
}

bool BlessedDominionEngine::DestroyDominionBlessed(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = std::remove_if(s_dominionBlesseds.begin(), s_dominionBlesseds.end(),
        [&dominionId](const auto& d) { return d->dominionId == dominionId; });
    if (it != s_dominionBlesseds.end()) {
        s_dominionBlesseds.erase(it, s_dominionBlesseds.end());
        return true;
    }
    return false;
}

std::shared_ptr<DominionBlessed> BlessedDominionEngine::GetDominionBlessed(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    for (auto& d : s_dominionBlesseds) {
        if (d->dominionId == dominionId) return d;
    }
    return nullptr;
}

std::vector<DominionBlessed> BlessedDominionEngine::GetAllDominionBlesseds() {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    std::vector<DominionBlessed> result;
    for (auto& d : s_dominionBlesseds) {
        result.push_back(*d);
    }
    return result;
}

bool BlessedDominionEngine::AssertAuthority(const std::string& dominionId, float amount) {
    auto d = GetDominionBlessed(dominionId);
    if (!d) return false;
    d->authority = std::min(1.0f, d->authority + amount);
    return true;
}

bool BlessedDominionEngine::ClaimSovereignty(const std::string& dominionId, float amount) {
    auto d = GetDominionBlessed(dominionId);
    if (!d) return false;
    d->sovereignty = std::min(1.0f, d->sovereignty + amount);
    return true;
}

bool BlessedDominionEngine::DeclareSovereign(const std::string& dominionId) {
    auto d = GetDominionBlessed(dominionId);
    if (!d) return false;
    d->isSovereign = true;
    return true;
}

// Grace Blessed operations
std::string BlessedDominionEngine::CreateGraceBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_graceMutex);
    auto grace = std::make_shared<GraceBlessed>();
    grace->graceId = "grace_" + std::to_string(++s_graceCounter);
    grace->name = name;
    grace->grace = 0.1f;
    grace->blessedness = 0.1f;
    grace->mercy = 0.1f;
    grace->kindness = 0.1f;
    grace->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_graceBlesseds.push_back(grace);
    return grace->graceId;
}

bool BlessedDominionEngine::DestroyGraceBlessed(const std::string& graceId) {
    std::lock_guard<std::mutex> lock(s_graceMutex);
    auto it = std::remove_if(s_graceBlesseds.begin(), s_graceBlesseds.end(),
        [&graceId](const auto& g) { return g->graceId == graceId; });
    if (it != s_graceBlesseds.end()) {
        s_graceBlesseds.erase(it, s_graceBlesseds.end());
        return true;
    }
    return false;
}

std::shared_ptr<GraceBlessed> BlessedDominionEngine::GetGraceBlessed(const std::string& graceId) {
    std::lock_guard<std::mutex> lock(s_graceMutex);
    for (auto& g : s_graceBlesseds) {
        if (g->graceId == graceId) return g;
    }
    return nullptr;
}

std::vector<GraceBlessed> BlessedDominionEngine::GetAllGraceBlesseds() {
    std::lock_guard<std::mutex> lock(s_graceMutex);
    std::vector<GraceBlessed> result;
    for (auto& g : s_graceBlesseds) {
        result.push_back(*g);
    }
    return result;
}

bool BlessedDominionEngine::ExtendMercy(const std::string& graceId, float amount) {
    auto g = GetGraceBlessed(graceId);
    if (!g) return false;
    g->mercy = std::min(1.0f, g->mercy + amount);
    return true;
}

bool BlessedDominionEngine::ShowKindness(const std::string& graceId, float amount) {
    auto g = GetGraceBlessed(graceId);
    if (!g) return false;
    g->kindness = std::min(1.0f, g->kindness + amount);
    return true;
}

// Favor Blessed operations
std::string BlessedDominionEngine::CreateFavorBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_favorMutex);
    auto favor = std::make_shared<FavorBlessed>();
    favor->favorId = "favor_" + std::to_string(++s_favorCounter);
    favor->name = name;
    favor->favor = 0.1f;
    favor->blessedness = 0.1f;
    favor->preference = 0.1f;
    favor->approval = 0.1f;
    favor->isPreferred = false;
    favor->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_favorBlesseds.push_back(favor);
    return favor->favorId;
}

bool BlessedDominionEngine::DestroyFavorBlessed(const std::string& favorId) {
    std::lock_guard<std::mutex> lock(s_favorMutex);
    auto it = std::remove_if(s_favorBlesseds.begin(), s_favorBlesseds.end(),
        [&favorId](const auto& f) { return f->favorId == favorId; });
    if (it != s_favorBlesseds.end()) {
        s_favorBlesseds.erase(it, s_favorBlesseds.end());
        return true;
    }
    return false;
}

std::shared_ptr<FavorBlessed> BlessedDominionEngine::GetFavorBlessed(const std::string& favorId) {
    std::lock_guard<std::mutex> lock(s_favorMutex);
    for (auto& f : s_favorBlesseds) {
        if (f->favorId == favorId) return f;
    }
    return nullptr;
}

std::vector<FavorBlessed> BlessedDominionEngine::GetAllFavorBlesseds() {
    std::lock_guard<std::mutex> lock(s_favorMutex);
    std::vector<FavorBlessed> result;
    for (auto& f : s_favorBlesseds) {
        result.push_back(*f);
    }
    return result;
}

bool BlessedDominionEngine::ExpressPreference(const std::string& favorId, float amount) {
    auto f = GetFavorBlessed(favorId);
    if (!f) return false;
    f->preference = std::min(1.0f, f->preference + amount);
    return true;
}

bool BlessedDominionEngine::GrantApproval(const std::string& favorId, float amount) {
    auto f = GetFavorBlessed(favorId);
    if (!f) return false;
    f->approval = std::min(1.0f, f->approval + amount);
    return true;
}

bool BlessedDominionEngine::DeclarePreferred(const std::string& favorId) {
    auto f = GetFavorBlessed(favorId);
    if (!f) return false;
    f->isPreferred = true;
    return true;
}

// Providence Blessed operations
std::string BlessedDominionEngine::CreateProvidenceBlessed(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_providenceMutex);
    auto providence = std::make_shared<ProvidenceBlessed>();
    providence->providenceId = "providence_" + std::to_string(++s_providenceCounter);
    providence->name = name;
    providence->providence = 0.1f;
    providence->blessedness = 0.1f;
    providence->guidance = 0.1f;
    providence->protection = 0.1f;
    providence->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_providenceBlesseds.push_back(providence);
    return providence->providenceId;
}

bool BlessedDominionEngine::DestroyProvidenceBlessed(const std::string& providenceId) {
    std::lock_guard<std::mutex> lock(s_providenceMutex);
    auto it = std::remove_if(s_providenceBlesseds.begin(), s_providenceBlesseds.end(),
        [&providenceId](const auto& p) { return p->providenceId == providenceId; });
    if (it != s_providenceBlesseds.end()) {
        s_providenceBlesseds.erase(it, s_providenceBlesseds.end());
        return true;
    }
    return false;
}

std::shared_ptr<ProvidenceBlessed> BlessedDominionEngine::GetProvidenceBlessed(const std::string& providenceId) {
    std::lock_guard<std::mutex> lock(s_providenceMutex);
    for (auto& p : s_providenceBlesseds) {
        if (p->providenceId == providenceId) return p;
    }
    return nullptr;
}

std::vector<ProvidenceBlessed> BlessedDominionEngine::GetAllProvidenceBlesseds() {
    std::lock_guard<std::mutex> lock(s_providenceMutex);
    std::vector<ProvidenceBlessed> result;
    for (auto& p : s_providenceBlesseds) {
        result.push_back(*p);
    }
    return result;
}

bool BlessedDominionEngine::OfferGuidance(const std::string& providenceId, float amount) {
    auto p = GetProvidenceBlessed(providenceId);
    if (!p) return false;
    p->guidance = std::min(1.0f, p->guidance + amount);
    return true;
}

bool BlessedDominionEngine::ExtendProtection(const std::string& providenceId, float amount) {
    auto p = GetProvidenceBlessed(providenceId);
    if (!p) return false;
    p->protection = std::min(1.0f, p->protection + amount);
    return true;
}

// Metrics and reporting
nlohmann::json BlessedDominionEngine::GetBlessedDominionMetrics() {
    nlohmann::json metrics;
    
    {
        std::lock_guard<std::mutex> lock(s_blessedMutex);
        metrics["blessedCount"] = s_blessedStructures.size();
        float totalBlessedness = 0.0f;
        int blessedBlesseds = 0;
        for (auto& s : s_blessedStructures) {
            totalBlessedness += s->blessedness;
            if (s->blessedness > 0.7f) blessedBlesseds++;
        }
        metrics["totalBlessedness"] = totalBlessedness;
        metrics["averageBlessedness"] = s_blessedStructures.empty() ? 0.0f : totalBlessedness / s_blessedStructures.size();
        metrics["blessedBlesseds"] = blessedBlesseds;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        metrics["dominionCount"] = s_dominionBlesseds.size();
        float totalDominion = 0.0f;
        int sovereignDominions = 0;
        for (auto& d : s_dominionBlesseds) {
            totalDominion += d->dominion;
            if (d->isSovereign) sovereignDominions++;
        }
        metrics["totalDominion"] = totalDominion;
        metrics["sovereignDominions"] = sovereignDominions;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_graceMutex);
        metrics["graceCount"] = s_graceBlesseds.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_favorMutex);
        metrics["favorCount"] = s_favorBlesseds.size();
        int preferredFavors = 0;
        for (auto& f : s_favorBlesseds) {
            if (f->isPreferred) preferredFavors++;
        }
        metrics["preferredFavors"] = preferredFavors;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_providenceMutex);
        metrics["providenceCount"] = s_providenceBlesseds.size();
    }
    
    return metrics;
}

nlohmann::json BlessedDominionEngine::GenerateBlessedDominionReport() {
    nlohmann::json report;
    report["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    report["metrics"] = GetBlessedDominionMetrics();
    
    {
        std::lock_guard<std::mutex> lock(s_blessedMutex);
        nlohmann::json structures = nlohmann::json::array();
        for (auto& s : s_blessedStructures) {
            structures.push_back(s->ToJson());
        }
        report["blessedStructures"] = structures;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        nlohmann::json dominions = nlohmann::json::array();
        for (auto& d : s_dominionBlesseds) {
            dominions.push_back(d->ToJson());
        }
        report["dominionBlesseds"] = dominions;
    }
    
    return report;
}

} // namespace BlessedDominion
