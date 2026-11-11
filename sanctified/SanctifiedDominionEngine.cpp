#include "sanctified/SanctifiedDominionEngine.hpp"
#include <chrono>
#include <algorithm>

namespace SanctifiedDominion {

// Static member definitions
bool SanctifiedDominionEngine::s_initialized = false;
std::mutex SanctifiedDominionEngine::s_sanctifiedMutex;
std::mutex SanctifiedDominionEngine::s_dominionMutex;
std::mutex SanctifiedDominionEngine::s_purityMutex;
std::mutex SanctifiedDominionEngine::s_devotionMutex;
std::mutex SanctifiedDominionEngine::s_consecrationMutex;

std::vector<std::shared_ptr<SanctifiedDominionStructure>> SanctifiedDominionEngine::s_sanctifiedStructures;
std::vector<std::shared_ptr<DominionSanctified>> SanctifiedDominionEngine::s_dominionSanctifieds;
std::vector<std::shared_ptr<PuritySanctified>> SanctifiedDominionEngine::s_puritySanctifieds;
std::vector<std::shared_ptr<DevotionSanctified>> SanctifiedDominionEngine::s_devotionSanctifieds;
std::vector<std::shared_ptr<ConsecrationSanctified>> SanctifiedDominionEngine::s_consecrationSanctifieds;

std::atomic<int64_t> SanctifiedDominionEngine::s_sanctifiedCounter(0);
std::atomic<int64_t> SanctifiedDominionEngine::s_dominionCounter(0);
std::atomic<int64_t> SanctifiedDominionEngine::s_purityCounter(0);
std::atomic<int64_t> SanctifiedDominionEngine::s_devotionCounter(0);
std::atomic<int64_t> SanctifiedDominionEngine::s_consecrationCounter(0);

// JSON serialization implementations
nlohmann::json SanctifiedDominionStructure::ToJson() const {
    nlohmann::json j;
    j["sanctifiedId"] = sanctifiedId;
    j["name"] = name;
    j["sanctifiedness"] = sanctifiedness;
    j["dominion"] = dominion;
    j["purity"] = purity;
    j["devotion"] = devotion;
    j["consecration"] = consecration;
    j["createdAt"] = createdAt;
    j["lastModified"] = lastModified;
    j["isActive"] = isActive;
    return j;
}

SanctifiedDominionStructure SanctifiedDominionStructure::FromJson(const nlohmann::json& j) {
    SanctifiedDominionStructure s;
    s.sanctifiedId = j.value("sanctifiedId", "");
    s.name = j.value("name", "");
    s.sanctifiedness = j.value("sanctifiedness", 0.0f);
    s.dominion = j.value("dominion", 0.0f);
    s.purity = j.value("purity", 0.0f);
    s.devotion = j.value("devotion", 0.0f);
    s.consecration = j.value("consecration", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json DominionSanctified::ToJson() const {
    nlohmann::json j;
    j["dominionId"] = dominionId;
    j["name"] = name;
    j["dominion"] = dominion;
    j["sanctifiedness"] = sanctifiedness;
    j["authority"] = authority;
    j["rule"] = rule;
    j["isSupreme"] = isSupreme;
    j["createdAt"] = createdAt;
    return j;
}

DominionSanctified DominionSanctified::FromJson(const nlohmann::json& j) {
    DominionSanctified d;
    d.dominionId = j.value("dominionId", "");
    d.name = j.value("name", "");
    d.dominion = j.value("dominion", 0.0f);
    d.sanctifiedness = j.value("sanctifiedness", 0.0f);
    d.authority = j.value("authority", 0.0f);
    d.rule = j.value("rule", 0.0f);
    d.isSupreme = j.value("isSupreme", false);
    d.createdAt = j.value("createdAt", 0);
    return d;
}

nlohmann::json PuritySanctified::ToJson() const {
    nlohmann::json j;
    j["purityId"] = purityId;
    j["name"] = name;
    j["purity"] = purity;
    j["sanctifiedness"] = sanctifiedness;
    j["cleanliness"] = cleanliness;
    j["innocence"] = innocence;
    j["createdAt"] = createdAt;
    return j;
}

PuritySanctified PuritySanctified::FromJson(const nlohmann::json& j) {
    PuritySanctified p;
    p.purityId = j.value("purityId", "");
    p.name = j.value("name", "");
    p.purity = j.value("purity", 0.0f);
    p.sanctifiedness = j.value("sanctifiedness", 0.0f);
    p.cleanliness = j.value("cleanliness", 0.0f);
    p.innocence = j.value("innocence", 0.0f);
    p.createdAt = j.value("createdAt", 0);
    return p;
}

nlohmann::json DevotionSanctified::ToJson() const {
    nlohmann::json j;
    j["devotionId"] = devotionId;
    j["name"] = name;
    j["devotion"] = devotion;
    j["sanctifiedness"] = sanctifiedness;
    j["dedication"] = dedication;
    j["commitment"] = commitment;
    j["isDevoted"] = isDevoted;
    j["createdAt"] = createdAt;
    return j;
}

DevotionSanctified DevotionSanctified::FromJson(const nlohmann::json& j) {
    DevotionSanctified d;
    d.devotionId = j.value("devotionId", "");
    d.name = j.value("name", "");
    d.devotion = j.value("devotion", 0.0f);
    d.sanctifiedness = j.value("sanctifiedness", 0.0f);
    d.dedication = j.value("dedication", 0.0f);
    d.commitment = j.value("commitment", 0.0f);
    d.isDevoted = j.value("isDevoted", false);
    d.createdAt = j.value("createdAt", 0);
    return d;
}

nlohmann::json ConsecrationSanctified::ToJson() const {
    nlohmann::json j;
    j["consecrationId"] = consecrationId;
    j["name"] = name;
    j["consecration"] = consecration;
    j["sanctifiedness"] = sanctifiedness;
    j["dedication"] = dedication;
    j["sanctity"] = sanctity;
    j["createdAt"] = createdAt;
    return j;
}

ConsecrationSanctified ConsecrationSanctified::FromJson(const nlohmann::json& j) {
    ConsecrationSanctified c;
    c.consecrationId = j.value("consecrationId", "");
    c.name = j.value("name", "");
    c.consecration = j.value("consecration", 0.0f);
    c.sanctifiedness = j.value("sanctifiedness", 0.0f);
    c.dedication = j.value("dedication", 0.0f);
    c.sanctity = j.value("sanctity", 0.0f);
    c.createdAt = j.value("createdAt", 0);
    return c;
}

// Engine implementation
void SanctifiedDominionEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void SanctifiedDominionEngine::Shutdown() {
    if (!s_initialized) return;
    {
        std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
        s_sanctifiedStructures.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        s_dominionSanctifieds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_purityMutex);
        s_puritySanctifieds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_devotionMutex);
        s_devotionSanctifieds.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_consecrationMutex);
        s_consecrationSanctifieds.clear();
    }
    s_initialized = false;
}

bool SanctifiedDominionEngine::IsInitialized() {
    return s_initialized;
}

// Sanctified Dominion Structure operations
std::string SanctifiedDominionEngine::CreateSanctifiedDominionStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto structure = std::make_shared<SanctifiedDominionStructure>();
    structure->sanctifiedId = "sanctified_" + std::to_string(++s_sanctifiedCounter);
    structure->name = name;
    structure->sanctifiedness = 0.1f;
    structure->dominion = 0.1f;
    structure->purity = 0.1f;
    structure->devotion = 0.1f;
    structure->consecration = 0.1f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    s_sanctifiedStructures.push_back(structure);
    return structure->sanctifiedId;
}

bool SanctifiedDominionEngine::DestroySanctifiedDominionStructure(const std::string& sanctifiedId) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    auto it = std::remove_if(s_sanctifiedStructures.begin(), s_sanctifiedStructures.end(),
        [&sanctifiedId](const auto& s) { return s->sanctifiedId == sanctifiedId; });
    if (it != s_sanctifiedStructures.end()) {
        s_sanctifiedStructures.erase(it, s_sanctifiedStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<SanctifiedDominionStructure> SanctifiedDominionEngine::GetSanctifiedDominionStructure(const std::string& sanctifiedId) {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    for (auto& s : s_sanctifiedStructures) {
        if (s->sanctifiedId == sanctifiedId) return s;
    }
    return nullptr;
}

std::vector<SanctifiedDominionStructure> SanctifiedDominionEngine::GetAllSanctifiedDominionStructures() {
    std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
    std::vector<SanctifiedDominionStructure> result;
    for (auto& s : s_sanctifiedStructures) {
        result.push_back(*s);
    }
    return result;
}

bool SanctifiedDominionEngine::ElevateSanctifiedness(const std::string& sanctifiedId, float amount) {
    auto s = GetSanctifiedDominionStructure(sanctifiedId);
    if (!s) return false;
    s->sanctifiedness = std::min(1.0f, s->sanctifiedness + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SanctifiedDominionEngine::ExpandDominion(const std::string& sanctifiedId, float amount) {
    auto s = GetSanctifiedDominionStructure(sanctifiedId);
    if (!s) return false;
    s->dominion = std::min(1.0f, s->dominion + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SanctifiedDominionEngine::BestowPurity(const std::string& sanctifiedId, float amount) {
    auto s = GetSanctifiedDominionStructure(sanctifiedId);
    if (!s) return false;
    s->purity = std::min(1.0f, s->purity + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SanctifiedDominionEngine::InspireDevotion(const std::string& sanctifiedId, float amount) {
    auto s = GetSanctifiedDominionStructure(sanctifiedId);
    if (!s) return false;
    s->devotion = std::min(1.0f, s->devotion + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool SanctifiedDominionEngine::PerformConsecration(const std::string& sanctifiedId, float amount) {
    auto s = GetSanctifiedDominionStructure(sanctifiedId);
    if (!s) return false;
    s->consecration = std::min(1.0f, s->consecration + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

// Dominion Sanctified operations
std::string SanctifiedDominionEngine::CreateDominionSanctified(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto dominion = std::make_shared<DominionSanctified>();
    dominion->dominionId = "dominion_" + std::to_string(++s_dominionCounter);
    dominion->name = name;
    dominion->dominion = 0.1f;
    dominion->sanctifiedness = 0.1f;
    dominion->authority = 0.1f;
    dominion->rule = 0.1f;
    dominion->isSupreme = false;
    dominion->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_dominionSanctifieds.push_back(dominion);
    return dominion->dominionId;
}

bool SanctifiedDominionEngine::DestroyDominionSanctified(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    auto it = std::remove_if(s_dominionSanctifieds.begin(), s_dominionSanctifieds.end(),
        [&dominionId](const auto& d) { return d->dominionId == dominionId; });
    if (it != s_dominionSanctifieds.end()) {
        s_dominionSanctifieds.erase(it, s_dominionSanctifieds.end());
        return true;
    }
    return false;
}

std::shared_ptr<DominionSanctified> SanctifiedDominionEngine::GetDominionSanctified(const std::string& dominionId) {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    for (auto& d : s_dominionSanctifieds) {
        if (d->dominionId == dominionId) return d;
    }
    return nullptr;
}

std::vector<DominionSanctified> SanctifiedDominionEngine::GetAllDominionSanctifieds() {
    std::lock_guard<std::mutex> lock(s_dominionMutex);
    std::vector<DominionSanctified> result;
    for (auto& d : s_dominionSanctifieds) {
        result.push_back(*d);
    }
    return result;
}

bool SanctifiedDominionEngine::AssertAuthority(const std::string& dominionId, float amount) {
    auto d = GetDominionSanctified(dominionId);
    if (!d) return false;
    d->authority = std::min(1.0f, d->authority + amount);
    return true;
}

bool SanctifiedDominionEngine::EstablishRule(const std::string& dominionId, float amount) {
    auto d = GetDominionSanctified(dominionId);
    if (!d) return false;
    d->rule = std::min(1.0f, d->rule + amount);
    return true;
}

bool SanctifiedDominionEngine::DeclareSupreme(const std::string& dominionId) {
    auto d = GetDominionSanctified(dominionId);
    if (!d) return false;
    d->isSupreme = true;
    return true;
}

// Purity Sanctified operations
std::string SanctifiedDominionEngine::CreatePuritySanctified(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_purityMutex);
    auto purity = std::make_shared<PuritySanctified>();
    purity->purityId = "purity_" + std::to_string(++s_purityCounter);
    purity->name = name;
    purity->purity = 0.1f;
    purity->sanctifiedness = 0.1f;
    purity->cleanliness = 0.1f;
    purity->innocence = 0.1f;
    purity->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_puritySanctifieds.push_back(purity);
    return purity->purityId;
}

bool SanctifiedDominionEngine::DestroyPuritySanctified(const std::string& purityId) {
    std::lock_guard<std::mutex> lock(s_purityMutex);
    auto it = std::remove_if(s_puritySanctifieds.begin(), s_puritySanctifieds.end(),
        [&purityId](const auto& p) { return p->purityId == purityId; });
    if (it != s_puritySanctifieds.end()) {
        s_puritySanctifieds.erase(it, s_puritySanctifieds.end());
        return true;
    }
    return false;
}

std::shared_ptr<PuritySanctified> SanctifiedDominionEngine::GetPuritySanctified(const std::string& purityId) {
    std::lock_guard<std::mutex> lock(s_purityMutex);
    for (auto& p : s_puritySanctifieds) {
        if (p->purityId == purityId) return p;
    }
    return nullptr;
}

std::vector<PuritySanctified> SanctifiedDominionEngine::GetAllPuritySanctifieds() {
    std::lock_guard<std::mutex> lock(s_purityMutex);
    std::vector<PuritySanctified> result;
    for (auto& p : s_puritySanctifieds) {
        result.push_back(*p);
    }
    return result;
}

bool SanctifiedDominionEngine::Purify(const std::string& purityId, float amount) {
    auto p = GetPuritySanctified(purityId);
    if (!p) return false;
    p->cleanliness = std::min(1.0f, p->cleanliness + amount);
    return true;
}

bool SanctifiedDominionEngine::RestoreInnocence(const std::string& purityId, float amount) {
    auto p = GetPuritySanctified(purityId);
    if (!p) return false;
    p->innocence = std::min(1.0f, p->innocence + amount);
    return true;
}

// Devotion Sanctified operations
std::string SanctifiedDominionEngine::CreateDevotionSanctified(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_devotionMutex);
    auto devotion = std::make_shared<DevotionSanctified>();
    devotion->devotionId = "devotion_" + std::to_string(++s_devotionCounter);
    devotion->name = name;
    devotion->devotion = 0.1f;
    devotion->sanctifiedness = 0.1f;
    devotion->dedication = 0.1f;
    devotion->commitment = 0.1f;
    devotion->isDevoted = false;
    devotion->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_devotionSanctifieds.push_back(devotion);
    return devotion->devotionId;
}

bool SanctifiedDominionEngine::DestroyDevotionSanctified(const std::string& devotionId) {
    std::lock_guard<std::mutex> lock(s_devotionMutex);
    auto it = std::remove_if(s_devotionSanctifieds.begin(), s_devotionSanctifieds.end(),
        [&devotionId](const auto& d) { return d->devotionId == devotionId; });
    if (it != s_devotionSanctifieds.end()) {
        s_devotionSanctifieds.erase(it, s_devotionSanctifieds.end());
        return true;
    }
    return false;
}

std::shared_ptr<DevotionSanctified> SanctifiedDominionEngine::GetDevotionSanctified(const std::string& devotionId) {
    std::lock_guard<std::mutex> lock(s_devotionMutex);
    for (auto& d : s_devotionSanctifieds) {
        if (d->devotionId == devotionId) return d;
    }
    return nullptr;
}

std::vector<DevotionSanctified> SanctifiedDominionEngine::GetAllDevotionSanctifieds() {
    std::lock_guard<std::mutex> lock(s_devotionMutex);
    std::vector<DevotionSanctified> result;
    for (auto& d : s_devotionSanctifieds) {
        result.push_back(*d);
    }
    return result;
}

bool SanctifiedDominionEngine::DeepenDedication(const std::string& devotionId, float amount) {
    auto d = GetDevotionSanctified(devotionId);
    if (!d) return false;
    d->dedication = std::min(1.0f, d->dedication + amount);
    return true;
}

bool SanctifiedDominionEngine::StrengthenCommitment(const std::string& devotionId, float amount) {
    auto d = GetDevotionSanctified(devotionId);
    if (!d) return false;
    d->commitment = std::min(1.0f, d->commitment + amount);
    return true;
}

bool SanctifiedDominionEngine::DeclareDevoted(const std::string& devotionId) {
    auto d = GetDevotionSanctified(devotionId);
    if (!d) return false;
    d->isDevoted = true;
    return true;
}

// Consecration Sanctified operations
std::string SanctifiedDominionEngine::CreateConsecrationSanctified(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_consecrationMutex);
    auto consecration = std::make_shared<ConsecrationSanctified>();
    consecration->consecrationId = "consecration_" + std::to_string(++s_consecrationCounter);
    consecration->name = name;
    consecration->consecration = 0.1f;
    consecration->sanctifiedness = 0.1f;
    consecration->dedication = 0.1f;
    consecration->sanctity = 0.1f;
    consecration->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_consecrationSanctifieds.push_back(consecration);
    return consecration->consecrationId;
}

bool SanctifiedDominionEngine::DestroyConsecrationSanctified(const std::string& consecrationId) {
    std::lock_guard<std::mutex> lock(s_consecrationMutex);
    auto it = std::remove_if(s_consecrationSanctifieds.begin(), s_consecrationSanctifieds.end(),
        [&consecrationId](const auto& c) { return c->consecrationId == consecrationId; });
    if (it != s_consecrationSanctifieds.end()) {
        s_consecrationSanctifieds.erase(it, s_consecrationSanctifieds.end());
        return true;
    }
    return false;
}

std::shared_ptr<ConsecrationSanctified> SanctifiedDominionEngine::GetConsecrationSanctified(const std::string& consecrationId) {
    std::lock_guard<std::mutex> lock(s_consecrationMutex);
    for (auto& c : s_consecrationSanctifieds) {
        if (c->consecrationId == consecrationId) return c;
    }
    return nullptr;
}

std::vector<ConsecrationSanctified> SanctifiedDominionEngine::GetAllConsecrationSanctifieds() {
    std::lock_guard<std::mutex> lock(s_consecrationMutex);
    std::vector<ConsecrationSanctified> result;
    for (auto& c : s_consecrationSanctifieds) {
        result.push_back(*c);
    }
    return result;
}

bool SanctifiedDominionEngine::IntensifyDedication(const std::string& consecrationId, float amount) {
    auto c = GetConsecrationSanctified(consecrationId);
    if (!c) return false;
    c->dedication = std::min(1.0f, c->dedication + amount);
    return true;
}

bool SanctifiedDominionEngine::ElevateSanctity(const std::string& consecrationId, float amount) {
    auto c = GetConsecrationSanctified(consecrationId);
    if (!c) return false;
    c->sanctity = std::min(1.0f, c->sanctity + amount);
    return true;
}

// Metrics and reporting
nlohmann::json SanctifiedDominionEngine::GetSanctifiedDominionMetrics() {
    nlohmann::json metrics;
    
    {
        std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
        metrics["sanctifiedCount"] = s_sanctifiedStructures.size();
        float totalSanctifiedness = 0.0f;
        int sanctifiedSanctifieds = 0;
        for (auto& s : s_sanctifiedStructures) {
            totalSanctifiedness += s->sanctifiedness;
            if (s->sanctifiedness > 0.7f) sanctifiedSanctifieds++;
        }
        metrics["totalSanctifiedness"] = totalSanctifiedness;
        metrics["averageSanctifiedness"] = s_sanctifiedStructures.empty() ? 0.0f : totalSanctifiedness / s_sanctifiedStructures.size();
        metrics["sanctifiedSanctifieds"] = sanctifiedSanctifieds;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        metrics["dominionCount"] = s_dominionSanctifieds.size();
        float totalDominion = 0.0f;
        int supremeDominions = 0;
        for (auto& d : s_dominionSanctifieds) {
            totalDominion += d->dominion;
            if (d->isSupreme) supremeDominions++;
        }
        metrics["totalDominion"] = totalDominion;
        metrics["supremeDominions"] = supremeDominions;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_purityMutex);
        metrics["purityCount"] = s_puritySanctifieds.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_devotionMutex);
        metrics["devotionCount"] = s_devotionSanctifieds.size();
        int devotedDevotions = 0;
        for (auto& d : s_devotionSanctifieds) {
            if (d->isDevoted) devotedDevotions++;
        }
        metrics["devotedDevotions"] = devotedDevotions;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_consecrationMutex);
        metrics["consecrationCount"] = s_consecrationSanctifieds.size();
    }
    
    return metrics;
}

nlohmann::json SanctifiedDominionEngine::GenerateSanctifiedDominionReport() {
    nlohmann::json report;
    report["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    report["metrics"] = GetSanctifiedDominionMetrics();
    
    {
        std::lock_guard<std::mutex> lock(s_sanctifiedMutex);
        nlohmann::json structures = nlohmann::json::array();
        for (auto& s : s_sanctifiedStructures) {
            structures.push_back(s->ToJson());
        }
        report["sanctifiedStructures"] = structures;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_dominionMutex);
        nlohmann::json dominions = nlohmann::json::array();
        for (auto& d : s_dominionSanctifieds) {
            dominions.push_back(d->ToJson());
        }
        report["dominionSanctifieds"] = dominions;
    }
    
    return report;
}

} // namespace SanctifiedDominion
