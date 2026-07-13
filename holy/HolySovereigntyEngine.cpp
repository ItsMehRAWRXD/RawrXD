#include "holy/HolySovereigntyEngine.hpp"
#include <chrono>
#include <algorithm>

namespace HolySovereignty {

// Static member definitions
bool HolySovereigntyEngine::s_initialized = false;
std::mutex HolySovereigntyEngine::s_holyMutex;
std::mutex HolySovereigntyEngine::s_sovereigntyMutex;
std::mutex HolySovereigntyEngine::s_gloryMutex;
std::mutex HolySovereigntyEngine::s_majestyMutex;
std::mutex HolySovereigntyEngine::s_powerMutex;

std::vector<std::shared_ptr<HolySovereigntyStructure>> HolySovereigntyEngine::s_holyStructures;
std::vector<std::shared_ptr<SovereigntyHoly>> HolySovereigntyEngine::s_sovereigntyHolies;
std::vector<std::shared_ptr<GloryHoly>> HolySovereigntyEngine::s_gloryHolies;
std::vector<std::shared_ptr<MajestyHoly>> HolySovereigntyEngine::s_majestyHolies;
std::vector<std::shared_ptr<PowerHoly>> HolySovereigntyEngine::s_powerHolies;

std::atomic<int64_t> HolySovereigntyEngine::s_holyCounter(0);
std::atomic<int64_t> HolySovereigntyEngine::s_sovereigntyCounter(0);
std::atomic<int64_t> HolySovereigntyEngine::s_gloryCounter(0);
std::atomic<int64_t> HolySovereigntyEngine::s_majestyCounter(0);
std::atomic<int64_t> HolySovereigntyEngine::s_powerCounter(0);

// JSON serialization implementations
nlohmann::json HolySovereigntyStructure::ToJson() const {
    nlohmann::json j;
    j["holyId"] = holyId;
    j["name"] = name;
    j["holiness"] = holiness;
    j["sovereignty"] = sovereignty;
    j["glory"] = glory;
    j["majesty"] = majesty;
    j["power"] = power;
    j["createdAt"] = createdAt;
    j["lastModified"] = lastModified;
    j["isActive"] = isActive;
    return j;
}

HolySovereigntyStructure HolySovereigntyStructure::FromJson(const nlohmann::json& j) {
    HolySovereigntyStructure s;
    s.holyId = j.value("holyId", "");
    s.name = j.value("name", "");
    s.holiness = j.value("holiness", 0.0f);
    s.sovereignty = j.value("sovereignty", 0.0f);
    s.glory = j.value("glory", 0.0f);
    s.majesty = j.value("majesty", 0.0f);
    s.power = j.value("power", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json SovereigntyHoly::ToJson() const {
    nlohmann::json j;
    j["sovereigntyId"] = sovereigntyId;
    j["name"] = name;
    j["sovereignty"] = sovereignty;
    j["holiness"] = holiness;
    j["supremacy"] = supremacy;
    j["dominion"] = dominion;
    j["isSupreme"] = isSupreme;
    j["createdAt"] = createdAt;
    return j;
}

SovereigntyHoly SovereigntyHoly::FromJson(const nlohmann::json& j) {
    SovereigntyHoly s;
    s.sovereigntyId = j.value("sovereigntyId", "");
    s.name = j.value("name", "");
    s.sovereignty = j.value("sovereignty", 0.0f);
    s.holiness = j.value("holiness", 0.0f);
    s.supremacy = j.value("supremacy", 0.0f);
    s.dominion = j.value("dominion", 0.0f);
    s.isSupreme = j.value("isSupreme", false);
    s.createdAt = j.value("createdAt", 0);
    return s;
}

nlohmann::json GloryHoly::ToJson() const {
    nlohmann::json j;
    j["gloryId"] = gloryId;
    j["name"] = name;
    j["glory"] = glory;
    j["holiness"] = holiness;
    j["brilliance"] = brilliance;
    j["splendor"] = splendor;
    j["createdAt"] = createdAt;
    return j;
}

GloryHoly GloryHoly::FromJson(const nlohmann::json& j) {
    GloryHoly g;
    g.gloryId = j.value("gloryId", "");
    g.name = j.value("name", "");
    g.glory = j.value("glory", 0.0f);
    g.holiness = j.value("holiness", 0.0f);
    g.brilliance = j.value("brilliance", 0.0f);
    g.splendor = j.value("splendor", 0.0f);
    g.createdAt = j.value("createdAt", 0);
    return g;
}

nlohmann::json MajestyHoly::ToJson() const {
    nlohmann::json j;
    j["majestyId"] = majestyId;
    j["name"] = name;
    j["majesty"] = majesty;
    j["holiness"] = holiness;
    j["grandeur"] = grandeur;
    j["dignity"] = dignity;
    j["isMajestic"] = isMajestic;
    j["createdAt"] = createdAt;
    return j;
}

MajestyHoly MajestyHoly::FromJson(const nlohmann::json& j) {
    MajestyHoly m;
    m.majestyId = j.value("majestyId", "");
    m.name = j.value("name", "");
    m.majesty = j.value("majesty", 0.0f);
    m.holiness = j.value("holiness", 0.0f);
    m.grandeur = j.value("grandeur", 0.0f);
    m.dignity = j.value("dignity", 0.0f);
    m.isMajestic = j.value("isMajestic", false);
    m.createdAt = j.value("createdAt", 0);
    return m;
}

nlohmann::json PowerHoly::ToJson() const {
    nlohmann::json j;
    j["powerId"] = powerId;
    j["name"] = name;
    j["power"] = power;
    j["holiness"] = holiness;
    j["strength"] = strength;
    j["might"] = might;
    j["createdAt"] = createdAt;
    return j;
}

PowerHoly PowerHoly::FromJson(const nlohmann::json& j) {
    PowerHoly p;
    p.powerId = j.value("powerId", "");
    p.name = j.value("name", "");
    p.power = j.value("power", 0.0f);
    p.holiness = j.value("holiness", 0.0f);
    p.strength = j.value("strength", 0.0f);
    p.might = j.value("might", 0.0f);
    p.createdAt = j.value("createdAt", 0);
    return p;
}

// Engine implementation
void HolySovereigntyEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void HolySovereigntyEngine::Shutdown() {
    if (!s_initialized) return;
    {
        std::lock_guard<std::mutex> lock(s_holyMutex);
        s_holyStructures.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
        s_sovereigntyHolies.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_gloryMutex);
        s_gloryHolies.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_majestyMutex);
        s_majestyHolies.clear();
    }
    {
        std::lock_guard<std::mutex> lock(s_powerMutex);
        s_powerHolies.clear();
    }
    s_initialized = false;
}

bool HolySovereigntyEngine::IsInitialized() {
    return s_initialized;
}

// Holy Sovereignty Structure operations
std::string HolySovereigntyEngine::CreateHolySovereigntyStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto structure = std::make_shared<HolySovereigntyStructure>();
    structure->holyId = "holy_" + std::to_string(++s_holyCounter);
    structure->name = name;
    structure->holiness = 0.1f;
    structure->sovereignty = 0.1f;
    structure->glory = 0.1f;
    structure->majesty = 0.1f;
    structure->power = 0.1f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    s_holyStructures.push_back(structure);
    return structure->holyId;
}

bool HolySovereigntyEngine::DestroyHolySovereigntyStructure(const std::string& holyId) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    auto it = std::remove_if(s_holyStructures.begin(), s_holyStructures.end(),
        [&holyId](const auto& s) { return s->holyId == holyId; });
    if (it != s_holyStructures.end()) {
        s_holyStructures.erase(it, s_holyStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<HolySovereigntyStructure> HolySovereigntyEngine::GetHolySovereigntyStructure(const std::string& holyId) {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    for (auto& s : s_holyStructures) {
        if (s->holyId == holyId) return s;
    }
    return nullptr;
}

std::vector<HolySovereigntyStructure> HolySovereigntyEngine::GetAllHolySovereigntyStructures() {
    std::lock_guard<std::mutex> lock(s_holyMutex);
    std::vector<HolySovereigntyStructure> result;
    for (auto& s : s_holyStructures) {
        result.push_back(*s);
    }
    return result;
}

bool HolySovereigntyEngine::ElevateHoliness(const std::string& holyId, float amount) {
    auto s = GetHolySovereigntyStructure(holyId);
    if (!s) return false;
    s->holiness = std::min(1.0f, s->holiness + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool HolySovereigntyEngine::ExpandSovereignty(const std::string& holyId, float amount) {
    auto s = GetHolySovereigntyStructure(holyId);
    if (!s) return false;
    s->sovereignty = std::min(1.0f, s->sovereignty + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool HolySovereigntyEngine::BestowGlory(const std::string& holyId, float amount) {
    auto s = GetHolySovereigntyStructure(holyId);
    if (!s) return false;
    s->glory = std::min(1.0f, s->glory + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool HolySovereigntyEngine::CrownMajesty(const std::string& holyId, float amount) {
    auto s = GetHolySovereigntyStructure(holyId);
    if (!s) return false;
    s->majesty = std::min(1.0f, s->majesty + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool HolySovereigntyEngine::ChannelPower(const std::string& holyId, float amount) {
    auto s = GetHolySovereigntyStructure(holyId);
    if (!s) return false;
    s->power = std::min(1.0f, s->power + amount);
    s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

// Sovereignty Holy operations
std::string HolySovereigntyEngine::CreateSovereigntyHoly(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    auto sovereignty = std::make_shared<SovereigntyHoly>();
    sovereignty->sovereigntyId = "sovereignty_" + std::to_string(++s_sovereigntyCounter);
    sovereignty->name = name;
    sovereignty->sovereignty = 0.1f;
    sovereignty->holiness = 0.1f;
    sovereignty->supremacy = 0.1f;
    sovereignty->dominion = 0.1f;
    sovereignty->isSupreme = false;
    sovereignty->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_sovereigntyHolies.push_back(sovereignty);
    return sovereignty->sovereigntyId;
}

bool HolySovereigntyEngine::DestroySovereigntyHoly(const std::string& sovereigntyId) {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    auto it = std::remove_if(s_sovereigntyHolies.begin(), s_sovereigntyHolies.end(),
        [&sovereigntyId](const auto& s) { return s->sovereigntyId == sovereigntyId; });
    if (it != s_sovereigntyHolies.end()) {
        s_sovereigntyHolies.erase(it, s_sovereigntyHolies.end());
        return true;
    }
    return false;
}

std::shared_ptr<SovereigntyHoly> HolySovereigntyEngine::GetSovereigntyHoly(const std::string& sovereigntyId) {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    for (auto& s : s_sovereigntyHolies) {
        if (s->sovereigntyId == sovereigntyId) return s;
    }
    return nullptr;
}

std::vector<SovereigntyHoly> HolySovereigntyEngine::GetAllSovereigntyHolies() {
    std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
    std::vector<SovereigntyHoly> result;
    for (auto& s : s_sovereigntyHolies) {
        result.push_back(*s);
    }
    return result;
}

bool HolySovereigntyEngine::AssertSupremacy(const std::string& sovereigntyId, float amount) {
    auto s = GetSovereigntyHoly(sovereigntyId);
    if (!s) return false;
    s->supremacy = std::min(1.0f, s->supremacy + amount);
    return true;
}

bool HolySovereigntyEngine::ExtendDominion(const std::string& sovereigntyId, float amount) {
    auto s = GetSovereigntyHoly(sovereigntyId);
    if (!s) return false;
    s->dominion = std::min(1.0f, s->dominion + amount);
    return true;
}

bool HolySovereigntyEngine::DeclareSupreme(const std::string& sovereigntyId) {
    auto s = GetSovereigntyHoly(sovereigntyId);
    if (!s) return false;
    s->isSupreme = true;
    return true;
}

// Glory Holy operations
std::string HolySovereigntyEngine::CreateGloryHoly(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_gloryMutex);
    auto glory = std::make_shared<GloryHoly>();
    glory->gloryId = "glory_" + std::to_string(++s_gloryCounter);
    glory->name = name;
    glory->glory = 0.1f;
    glory->holiness = 0.1f;
    glory->brilliance = 0.1f;
    glory->splendor = 0.1f;
    glory->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_gloryHolies.push_back(glory);
    return glory->gloryId;
}

bool HolySovereigntyEngine::DestroyGloryHoly(const std::string& gloryId) {
    std::lock_guard<std::mutex> lock(s_gloryMutex);
    auto it = std::remove_if(s_gloryHolies.begin(), s_gloryHolies.end(),
        [&gloryId](const auto& g) { return g->gloryId == gloryId; });
    if (it != s_gloryHolies.end()) {
        s_gloryHolies.erase(it, s_gloryHolies.end());
        return true;
    }
    return false;
}

std::shared_ptr<GloryHoly> HolySovereigntyEngine::GetGloryHoly(const std::string& gloryId) {
    std::lock_guard<std::mutex> lock(s_gloryMutex);
    for (auto& g : s_gloryHolies) {
        if (g->gloryId == gloryId) return g;
    }
    return nullptr;
}

std::vector<GloryHoly> HolySovereigntyEngine::GetAllGloryHolies() {
    std::lock_guard<std::mutex> lock(s_gloryMutex);
    std::vector<GloryHoly> result;
    for (auto& g : s_gloryHolies) {
        result.push_back(*g);
    }
    return result;
}

bool HolySovereigntyEngine::RadiateBrilliance(const std::string& gloryId, float amount) {
    auto g = GetGloryHoly(gloryId);
    if (!g) return false;
    g->brilliance = std::min(1.0f, g->brilliance + amount);
    return true;
}

bool HolySovereigntyEngine::ManifestSplendor(const std::string& gloryId, float amount) {
    auto g = GetGloryHoly(gloryId);
    if (!g) return false;
    g->splendor = std::min(1.0f, g->splendor + amount);
    return true;
}

// Majesty Holy operations
std::string HolySovereigntyEngine::CreateMajestyHoly(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_majestyMutex);
    auto majesty = std::make_shared<MajestyHoly>();
    majesty->majestyId = "majesty_" + std::to_string(++s_majestyCounter);
    majesty->name = name;
    majesty->majesty = 0.1f;
    majesty->holiness = 0.1f;
    majesty->grandeur = 0.1f;
    majesty->dignity = 0.1f;
    majesty->isMajestic = false;
    majesty->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_majestyHolies.push_back(majesty);
    return majesty->majestyId;
}

bool HolySovereigntyEngine::DestroyMajestyHoly(const std::string& majestyId) {
    std::lock_guard<std::mutex> lock(s_majestyMutex);
    auto it = std::remove_if(s_majestyHolies.begin(), s_majestyHolies.end(),
        [&majestyId](const auto& m) { return m->majestyId == majestyId; });
    if (it != s_majestyHolies.end()) {
        s_majestyHolies.erase(it, s_majestyHolies.end());
        return true;
    }
    return false;
}

std::shared_ptr<MajestyHoly> HolySovereigntyEngine::GetMajestyHoly(const std::string& majestyId) {
    std::lock_guard<std::mutex> lock(s_majestyMutex);
    for (auto& m : s_majestyHolies) {
        if (m->majestyId == majestyId) return m;
    }
    return nullptr;
}

std::vector<MajestyHoly> HolySovereigntyEngine::GetAllMajestyHolies() {
    std::lock_guard<std::mutex> lock(s_majestyMutex);
    std::vector<MajestyHoly> result;
    for (auto& m : s_majestyHolies) {
        result.push_back(*m);
    }
    return result;
}

bool HolySovereigntyEngine::ExaltGrandeur(const std::string& majestyId, float amount) {
    auto m = GetMajestyHoly(majestyId);
    if (!m) return false;
    m->grandeur = std::min(1.0f, m->grandeur + amount);
    return true;
}

bool HolySovereigntyEngine::UpholdDignity(const std::string& majestyId, float amount) {
    auto m = GetMajestyHoly(majestyId);
    if (!m) return false;
    m->dignity = std::min(1.0f, m->dignity + amount);
    return true;
}

bool HolySovereigntyEngine::DeclareMajestic(const std::string& majestyId) {
    auto m = GetMajestyHoly(majestyId);
    if (!m) return false;
    m->isMajestic = true;
    return true;
}

// Power Holy operations
std::string HolySovereigntyEngine::CreatePowerHoly(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_powerMutex);
    auto power = std::make_shared<PowerHoly>();
    power->powerId = "power_" + std::to_string(++s_powerCounter);
    power->name = name;
    power->power = 0.1f;
    power->holiness = 0.1f;
    power->strength = 0.1f;
    power->might = 0.1f;
    power->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    s_powerHolies.push_back(power);
    return power->powerId;
}

bool HolySovereigntyEngine::DestroyPowerHoly(const std::string& powerId) {
    std::lock_guard<std::mutex> lock(s_powerMutex);
    auto it = std::remove_if(s_powerHolies.begin(), s_powerHolies.end(),
        [&powerId](const auto& p) { return p->powerId == powerId; });
    if (it != s_powerHolies.end()) {
        s_powerHolies.erase(it, s_powerHolies.end());
        return true;
    }
    return false;
}

std::shared_ptr<PowerHoly> HolySovereigntyEngine::GetPowerHoly(const std::string& powerId) {
    std::lock_guard<std::mutex> lock(s_powerMutex);
    for (auto& p : s_powerHolies) {
        if (p->powerId == powerId) return p;
    }
    return nullptr;
}

std::vector<PowerHoly> HolySovereigntyEngine::GetAllPowerHolies() {
    std::lock_guard<std::mutex> lock(s_powerMutex);
    std::vector<PowerHoly> result;
    for (auto& p : s_powerHolies) {
        result.push_back(*p);
    }
    return result;
}

bool HolySovereigntyEngine::FortifyStrength(const std::string& powerId, float amount) {
    auto p = GetPowerHoly(powerId);
    if (!p) return false;
    p->strength = std::min(1.0f, p->strength + amount);
    return true;
}

bool HolySovereigntyEngine::DemonstrateMight(const std::string& powerId, float amount) {
    auto p = GetPowerHoly(powerId);
    if (!p) return false;
    p->might = std::min(1.0f, p->might + amount);
    return true;
}

// Metrics and reporting
nlohmann::json HolySovereigntyEngine::GetHolySovereigntyMetrics() {
    nlohmann::json metrics;
    
    {
        std::lock_guard<std::mutex> lock(s_holyMutex);
        metrics["holyCount"] = s_holyStructures.size();
        float totalHoliness = 0.0f;
        int holyHolies = 0;
        for (auto& s : s_holyStructures) {
            totalHoliness += s->holiness;
            if (s->holiness > 0.7f) holyHolies++;
        }
        metrics["totalHoliness"] = totalHoliness;
        metrics["averageHoliness"] = s_holyStructures.empty() ? 0.0f : totalHoliness / s_holyStructures.size();
        metrics["holyHolies"] = holyHolies;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
        metrics["sovereigntyCount"] = s_sovereigntyHolies.size();
        float totalSovereignty = 0.0f;
        int supremeSovereignties = 0;
        for (auto& s : s_sovereigntyHolies) {
            totalSovereignty += s->sovereignty;
            if (s->isSupreme) supremeSovereignties++;
        }
        metrics["totalSovereignty"] = totalSovereignty;
        metrics["supremeSovereignties"] = supremeSovereignties;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_gloryMutex);
        metrics["gloryCount"] = s_gloryHolies.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(s_majestyMutex);
        metrics["majestyCount"] = s_majestyHolies.size();
        int majesticMajesties = 0;
        for (auto& m : s_majestyHolies) {
            if (m->isMajestic) majesticMajesties++;
        }
        metrics["majesticMajesties"] = majesticMajesties;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_powerMutex);
        metrics["powerCount"] = s_powerHolies.size();
    }
    
    return metrics;
}

nlohmann::json HolySovereigntyEngine::GenerateHolySovereigntyReport() {
    nlohmann::json report;
    report["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    report["metrics"] = GetHolySovereigntyMetrics();
    
    {
        std::lock_guard<std::mutex> lock(s_holyMutex);
        nlohmann::json structures = nlohmann::json::array();
        for (auto& s : s_holyStructures) {
            structures.push_back(s->ToJson());
        }
        report["holyStructures"] = structures;
    }
    
    {
        std::lock_guard<std::mutex> lock(s_sovereigntyMutex);
        nlohmann::json sovereignties = nlohmann::json::array();
        for (auto& s : s_sovereigntyHolies) {
            sovereignties.push_back(s->ToJson());
        }
        report["sovereigntyHolies"] = sovereignties;
    }
    
    return report;
}

} // namespace HolySovereignty
