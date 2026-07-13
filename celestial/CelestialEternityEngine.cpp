#include "CelestialEternityEngine.hpp"
#include <chrono>
#include <algorithm>

namespace CelestialEternity {

// Static member definitions
bool CelestialEternityEngine::s_initialized = false;
std::mutex CelestialEternityEngine::s_celestialMutex;
std::mutex CelestialEternityEngine::s_eternityMutex;
std::mutex CelestialEternityEngine::s_cosmosMutex;
std::mutex CelestialEternityEngine::s_firmamentMutex;
std::mutex CelestialEternityEngine::s_aetherMutex;

std::vector<std::shared_ptr<CelestialEternityStructure>> CelestialEternityEngine::s_celestialStructures;
std::vector<std::shared_ptr<EternityCelestial>> CelestialEternityEngine::s_eternityCelestials;
std::vector<std::shared_ptr<CosmosCelestial>> CelestialEternityEngine::s_cosmosCelestials;
std::vector<std::shared_ptr<FirmamentCelestial>> CelestialEternityEngine::s_firmamentCelestials;
std::vector<std::shared_ptr<AetherCelestial>> CelestialEternityEngine::s_aetherCelestials;

std::atomic<int64_t> CelestialEternityEngine::s_celestialCounter{0};
std::atomic<int64_t> CelestialEternityEngine::s_eternityCounter{0};
std::atomic<int64_t> CelestialEternityEngine::s_cosmosCounter{0};
std::atomic<int64_t> CelestialEternityEngine::s_firmamentCounter{0};
std::atomic<int64_t> CelestialEternityEngine::s_aetherCounter{0};

// JSON serialization implementations
nlohmann::json CelestialEternityStructure::ToJson() const {
    return {
        {"celestialId", celestialId},
        {"name", name},
        {"celestialness", celestialness},
        {"eternity", eternity},
        {"cosmos", cosmos},
        {"firmament", firmament},
        {"aether", aether},
        {"createdAt", createdAt},
        {"lastModified", lastModified},
        {"isActive", isActive}
    };
}

CelestialEternityStructure CelestialEternityStructure::FromJson(const nlohmann::json& j) {
    CelestialEternityStructure s;
    s.celestialId = j.value("celestialId", "");
    s.name = j.value("name", "");
    s.celestialness = j.value("celestialness", 0.0f);
    s.eternity = j.value("eternity", 0.0f);
    s.cosmos = j.value("cosmos", 0.0f);
    s.firmament = j.value("firmament", 0.0f);
    s.aether = j.value("aether", 0.0f);
    s.createdAt = j.value("createdAt", 0);
    s.lastModified = j.value("lastModified", 0);
    s.isActive = j.value("isActive", true);
    return s;
}

nlohmann::json EternityCelestial::ToJson() const {
    return {
        {"eternityId", eternityId},
        {"name", name},
        {"eternity", eternity},
        {"celestialness", celestialness},
        {"infinity", infinity},
        {"perpetuity", perpetuity},
        {"isEternal", isEternal},
        {"createdAt", createdAt}
    };
}

EternityCelestial EternityCelestial::FromJson(const nlohmann::json& j) {
    EternityCelestial e;
    e.eternityId = j.value("eternityId", "");
    e.name = j.value("name", "");
    e.eternity = j.value("eternity", 0.0f);
    e.celestialness = j.value("celestialness", 0.0f);
    e.infinity = j.value("infinity", 0.0f);
    e.perpetuity = j.value("perpetuity", 0.0f);
    e.isEternal = j.value("isEternal", false);
    e.createdAt = j.value("createdAt", 0);
    return e;
}

nlohmann::json CosmosCelestial::ToJson() const {
    return {
        {"cosmosId", cosmosId},
        {"name", name},
        {"cosmos", cosmos},
        {"celestialness", celestialness},
        {"universe", universe},
        {"expanse", expanse},
        {"createdAt", createdAt}
    };
}

CosmosCelestial CosmosCelestial::FromJson(const nlohmann::json& j) {
    CosmosCelestial c;
    c.cosmosId = j.value("cosmosId", "");
    c.name = j.value("name", "");
    c.cosmos = j.value("cosmos", 0.0f);
    c.celestialness = j.value("celestialness", 0.0f);
    c.universe = j.value("universe", 0.0f);
    c.expanse = j.value("expanse", 0.0f);
    c.createdAt = j.value("createdAt", 0);
    return c;
}

nlohmann::json FirmamentCelestial::ToJson() const {
    return {
        {"firmamentId", firmamentId},
        {"name", name},
        {"firmament", firmament},
        {"celestialness", celestialness},
        {"vault", vault},
        {"canopy", canopy},
        {"isVaulted", isVaulted},
        {"createdAt", createdAt}
    };
}

FirmamentCelestial FirmamentCelestial::FromJson(const nlohmann::json& j) {
    FirmamentCelestial f;
    f.firmamentId = j.value("firmamentId", "");
    f.name = j.value("name", "");
    f.firmament = j.value("firmament", 0.0f);
    f.celestialness = j.value("celestialness", 0.0f);
    f.vault = j.value("vault", 0.0f);
    f.canopy = j.value("canopy", 0.0f);
    f.isVaulted = j.value("isVaulted", false);
    f.createdAt = j.value("createdAt", 0);
    return f;
}

nlohmann::json AetherCelestial::ToJson() const {
    return {
        {"aetherId", aetherId},
        {"name", name},
        {"aether", aether},
        {"celestialness", celestialness},
        {"quintessence", quintessence},
        {"essence", essence},
        {"createdAt", createdAt}
    };
}

AetherCelestial AetherCelestial::FromJson(const nlohmann::json& j) {
    AetherCelestial a;
    a.aetherId = j.value("aetherId", "");
    a.name = j.value("name", "");
    a.aether = j.value("aether", 0.0f);
    a.celestialness = j.value("celestialness", 0.0f);
    a.quintessence = j.value("quintessence", 0.0f);
    a.essence = j.value("essence", 0.0f);
    a.createdAt = j.value("createdAt", 0);
    return a;
}

// Engine implementation
void CelestialEternityEngine::Init() {
    if (s_initialized) return;
    s_initialized = true;
}

void CelestialEternityEngine::Shutdown() {
    if (!s_initialized) return;
    
    std::lock_guard<std::mutex> lock1(s_celestialMutex);
    std::lock_guard<std::mutex> lock2(s_eternityMutex);
    std::lock_guard<std::mutex> lock3(s_cosmosMutex);
    std::lock_guard<std::mutex> lock4(s_firmamentMutex);
    std::lock_guard<std::mutex> lock5(s_aetherMutex);
    
    s_celestialStructures.clear();
    s_eternityCelestials.clear();
    s_cosmosCelestials.clear();
    s_firmamentCelestials.clear();
    s_aetherCelestials.clear();
    
    s_initialized = false;
}

bool CelestialEternityEngine::IsInitialized() {
    return s_initialized;
}

// Celestial Eternity Structure operations
std::string CelestialEternityEngine::CreateCelestialEternityStructure(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    auto structure = std::make_shared<CelestialEternityStructure>();
    structure->celestialId = "celestial_" + std::to_string(s_celestialCounter++);
    structure->name = name;
    structure->celestialness = 0.0f;
    structure->eternity = 0.0f;
    structure->cosmos = 0.0f;
    structure->firmament = 0.0f;
    structure->aether = 0.0f;
    structure->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    structure->lastModified = structure->createdAt;
    structure->isActive = true;
    
    s_celestialStructures.push_back(structure);
    return structure->celestialId;
}

bool CelestialEternityEngine::DestroyCelestialEternityStructure(const std::string& celestialId) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    auto it = std::remove_if(s_celestialStructures.begin(), s_celestialStructures.end(),
        [&celestialId](const auto& s) { return s->celestialId == celestialId; });
    
    if (it != s_celestialStructures.end()) {
        s_celestialStructures.erase(it, s_celestialStructures.end());
        return true;
    }
    return false;
}

std::shared_ptr<CelestialEternityStructure> CelestialEternityEngine::GetCelestialEternityStructure(const std::string& celestialId) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    for (auto& s : s_celestialStructures) {
        if (s->celestialId == celestialId) {
            return s;
        }
    }
    return nullptr;
}

std::vector<CelestialEternityStructure> CelestialEternityEngine::GetAllCelestialEternityStructures() {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    std::vector<CelestialEternityStructure> result;
    for (auto& s : s_celestialStructures) {
        result.push_back(*s);
    }
    return result;
}

bool CelestialEternityEngine::ElevateCelestialness(const std::string& celestialId, float amount) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    for (auto& s : s_celestialStructures) {
        if (s->celestialId == celestialId) {
            s->celestialness = std::min(1.0f, s->celestialness + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::ExpandEternity(const std::string& celestialId, float amount) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    for (auto& s : s_celestialStructures) {
        if (s->celestialId == celestialId) {
            s->eternity = std::min(1.0f, s->eternity + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::UnfoldCosmos(const std::string& celestialId, float amount) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    for (auto& s : s_celestialStructures) {
        if (s->celestialId == celestialId) {
            s->cosmos = std::min(1.0f, s->cosmos + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::RaiseFirmament(const std::string& celestialId, float amount) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    for (auto& s : s_celestialStructures) {
        if (s->celestialId == celestialId) {
            s->firmament = std::min(1.0f, s->firmament + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::RefineAether(const std::string& celestialId, float amount) {
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    
    for (auto& s : s_celestialStructures) {
        if (s->celestialId == celestialId) {
            s->aether = std::min(1.0f, s->aether + amount);
            s->lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
    }
    return false;
}

// Eternity Celestial operations
std::string CelestialEternityEngine::CreateEternityCelestial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_eternityMutex);
    
    auto eternity = std::make_shared<EternityCelestial>();
    eternity->eternityId = "eternity_" + std::to_string(s_eternityCounter++);
    eternity->name = name;
    eternity->eternity = 0.0f;
    eternity->celestialness = 0.0f;
    eternity->infinity = 0.0f;
    eternity->perpetuity = 0.0f;
    eternity->isEternal = false;
    eternity->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_eternityCelestials.push_back(eternity);
    return eternity->eternityId;
}

bool CelestialEternityEngine::DestroyEternityCelestial(const std::string& eternityId) {
    std::lock_guard<std::mutex> lock(s_eternityMutex);
    
    auto it = std::remove_if(s_eternityCelestials.begin(), s_eternityCelestials.end(),
        [&eternityId](const auto& e) { return e->eternityId == eternityId; });
    
    if (it != s_eternityCelestials.end()) {
        s_eternityCelestials.erase(it, s_eternityCelestials.end());
        return true;
    }
    return false;
}

std::shared_ptr<EternityCelestial> CelestialEternityEngine::GetEternityCelestial(const std::string& eternityId) {
    std::lock_guard<std::mutex> lock(s_eternityMutex);
    
    for (auto& e : s_eternityCelestials) {
        if (e->eternityId == eternityId) {
            return e;
        }
    }
    return nullptr;
}

std::vector<EternityCelestial> CelestialEternityEngine::GetAllEternityCelestials() {
    std::lock_guard<std::mutex> lock(s_eternityMutex);
    
    std::vector<EternityCelestial> result;
    for (auto& e : s_eternityCelestials) {
        result.push_back(*e);
    }
    return result;
}

bool CelestialEternityEngine::ExtendInfinity(const std::string& eternityId, float amount) {
    std::lock_guard<std::mutex> lock(s_eternityMutex);
    
    for (auto& e : s_eternityCelestials) {
        if (e->eternityId == eternityId) {
            e->infinity = std::min(1.0f, e->infinity + amount);
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::EnsurePerpetuity(const std::string& eternityId, float amount) {
    std::lock_guard<std::mutex> lock(s_eternityMutex);
    
    for (auto& e : s_eternityCelestials) {
        if (e->eternityId == eternityId) {
            e->perpetuity = std::min(1.0f, e->perpetuity + amount);
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::DeclareEternal(const std::string& eternityId) {
    std::lock_guard<std::mutex> lock(s_eternityMutex);
    
    for (auto& e : s_eternityCelestials) {
        if (e->eternityId == eternityId) {
            e->isEternal = true;
            e->eternity = 1.0f;
            return true;
        }
    }
    return false;
}

// Cosmos Celestial operations
std::string CelestialEternityEngine::CreateCosmosCelestial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_cosmosMutex);
    
    auto cosmos = std::make_shared<CosmosCelestial>();
    cosmos->cosmosId = "cosmos_" + std::to_string(s_cosmosCounter++);
    cosmos->name = name;
    cosmos->cosmos = 0.0f;
    cosmos->celestialness = 0.0f;
    cosmos->universe = 0.0f;
    cosmos->expanse = 0.0f;
    cosmos->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_cosmosCelestials.push_back(cosmos);
    return cosmos->cosmosId;
}

bool CelestialEternityEngine::DestroyCosmosCelestial(const std::string& cosmosId) {
    std::lock_guard<std::mutex> lock(s_cosmosMutex);
    
    auto it = std::remove_if(s_cosmosCelestials.begin(), s_cosmosCelestials.end(),
        [&cosmosId](const auto& c) { return c->cosmosId == cosmosId; });
    
    if (it != s_cosmosCelestials.end()) {
        s_cosmosCelestials.erase(it, s_cosmosCelestials.end());
        return true;
    }
    return false;
}

std::shared_ptr<CosmosCelestial> CelestialEternityEngine::GetCosmosCelestial(const std::string& cosmosId) {
    std::lock_guard<std::mutex> lock(s_cosmosMutex);
    
    for (auto& c : s_cosmosCelestials) {
        if (c->cosmosId == cosmosId) {
            return c;
        }
    }
    return nullptr;
}

std::vector<CosmosCelestial> CelestialEternityEngine::GetAllCosmosCelestials() {
    std::lock_guard<std::mutex> lock(s_cosmosMutex);
    
    std::vector<CosmosCelestial> result;
    for (auto& c : s_cosmosCelestials) {
        result.push_back(*c);
    }
    return result;
}

bool CelestialEternityEngine::ExpandUniverse(const std::string& cosmosId, float amount) {
    std::lock_guard<std::mutex> lock(s_cosmosMutex);
    
    for (auto& c : s_cosmosCelestials) {
        if (c->cosmosId == cosmosId) {
            c->universe = std::min(1.0f, c->universe + amount);
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::WidenExpanse(const std::string& cosmosId, float amount) {
    std::lock_guard<std::mutex> lock(s_cosmosMutex);
    
    for (auto& c : s_cosmosCelestials) {
        if (c->cosmosId == cosmosId) {
            c->expanse = std::min(1.0f, c->expanse + amount);
            return true;
        }
    }
    return false;
}

// Firmament Celestial operations
std::string CelestialEternityEngine::CreateFirmamentCelestial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_firmamentMutex);
    
    auto firmament = std::make_shared<FirmamentCelestial>();
    firmament->firmamentId = "firmament_" + std::to_string(s_firmamentCounter++);
    firmament->name = name;
    firmament->firmament = 0.0f;
    firmament->celestialness = 0.0f;
    firmament->vault = 0.0f;
    firmament->canopy = 0.0f;
    firmament->isVaulted = false;
    firmament->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_firmamentCelestials.push_back(firmament);
    return firmament->firmamentId;
}

bool CelestialEternityEngine::DestroyFirmamentCelestial(const std::string& firmamentId) {
    std::lock_guard<std::mutex> lock(s_firmamentMutex);
    
    auto it = std::remove_if(s_firmamentCelestials.begin(), s_firmamentCelestials.end(),
        [&firmamentId](const auto& f) { return f->firmamentId == firmamentId; });
    
    if (it != s_firmamentCelestials.end()) {
        s_firmamentCelestials.erase(it, s_firmamentCelestials.end());
        return true;
    }
    return false;
}

std::shared_ptr<FirmamentCelestial> CelestialEternityEngine::GetFirmamentCelestial(const std::string& firmamentId) {
    std::lock_guard<std::mutex> lock(s_firmamentMutex);
    
    for (auto& f : s_firmamentCelestials) {
        if (f->firmamentId == firmamentId) {
            return f;
        }
    }
    return nullptr;
}

std::vector<FirmamentCelestial> CelestialEternityEngine::GetAllFirmamentCelestials() {
    std::lock_guard<std::mutex> lock(s_firmamentMutex);
    
    std::vector<FirmamentCelestial> result;
    for (auto& f : s_firmamentCelestials) {
        result.push_back(*f);
    }
    return result;
}

bool CelestialEternityEngine::FortifyVault(const std::string& firmamentId, float amount) {
    std::lock_guard<std::mutex> lock(s_firmamentMutex);
    
    for (auto& f : s_firmamentCelestials) {
        if (f->firmamentId == firmamentId) {
            f->vault = std::min(1.0f, f->vault + amount);
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::ExtendCanopy(const std::string& firmamentId, float amount) {
    std::lock_guard<std::mutex> lock(s_firmamentMutex);
    
    for (auto& f : s_firmamentCelestials) {
        if (f->firmamentId == firmamentId) {
            f->canopy = std::min(1.0f, f->canopy + amount);
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::DeclareVaulted(const std::string& firmamentId) {
    std::lock_guard<std::mutex> lock(s_firmamentMutex);
    
    for (auto& f : s_firmamentCelestials) {
        if (f->firmamentId == firmamentId) {
            f->isVaulted = true;
            f->firmament = 1.0f;
            return true;
        }
    }
    return false;
}

// Aether Celestial operations
std::string CelestialEternityEngine::CreateAetherCelestial(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_aetherMutex);
    
    auto aether = std::make_shared<AetherCelestial>();
    aether->aetherId = "aether_" + std::to_string(s_aetherCounter++);
    aether->name = name;
    aether->aether = 0.0f;
    aether->celestialness = 0.0f;
    aether->quintessence = 0.0f;
    aether->essence = 0.0f;
    aether->createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_aetherCelestials.push_back(aether);
    return aether->aetherId;
}

bool CelestialEternityEngine::DestroyAetherCelestial(const std::string& aetherId) {
    std::lock_guard<std::mutex> lock(s_aetherMutex);
    
    auto it = std::remove_if(s_aetherCelestials.begin(), s_aetherCelestials.end(),
        [&aetherId](const auto& a) { return a->aetherId == aetherId; });
    
    if (it != s_aetherCelestials.end()) {
        s_aetherCelestials.erase(it, s_aetherCelestials.end());
        return true;
    }
    return false;
}

std::shared_ptr<AetherCelestial> CelestialEternityEngine::GetAetherCelestial(const std::string& aetherId) {
    std::lock_guard<std::mutex> lock(s_aetherMutex);
    
    for (auto& a : s_aetherCelestials) {
        if (a->aetherId == aetherId) {
            return a;
        }
    }
    return nullptr;
}

std::vector<AetherCelestial> CelestialEternityEngine::GetAllAetherCelestials() {
    std::lock_guard<std::mutex> lock(s_aetherMutex);
    
    std::vector<AetherCelestial> result;
    for (auto& a : s_aetherCelestials) {
        result.push_back(*a);
    }
    return result;
}

bool CelestialEternityEngine::DistillQuintessence(const std::string& aetherId, float amount) {
    std::lock_guard<std::mutex> lock(s_aetherMutex);
    
    for (auto& a : s_aetherCelestials) {
        if (a->aetherId == aetherId) {
            a->quintessence = std::min(1.0f, a->quintessence + amount);
            return true;
        }
    }
    return false;
}

bool CelestialEternityEngine::PurifyEssence(const std::string& aetherId, float amount) {
    std::lock_guard<std::mutex> lock(s_aetherMutex);
    
    for (auto& a : s_aetherCelestials) {
        if (a->aetherId == aetherId) {
            a->essence = std::min(1.0f, a->essence + amount);
            return true;
        }
    }
    return false;
}

// Metrics and reporting
nlohmann::json CelestialEternityEngine::GetCelestialEternityMetrics() {
    std::lock_guard<std::mutex> lock1(s_celestialMutex);
    std::lock_guard<std::mutex> lock2(s_eternityMutex);
    std::lock_guard<std::mutex> lock3(s_cosmosMutex);
    std::lock_guard<std::mutex> lock4(s_firmamentMutex);
    std::lock_guard<std::mutex> lock5(s_aetherMutex);
    
    float totalCelestialness = 0.0f, totalEternity = 0.0f, totalCosmos = 0.0f, totalFirmament = 0.0f, totalAether = 0.0f;
    
    for (auto& s : s_celestialStructures) {
        totalCelestialness += s->celestialness;
        totalEternity += s->eternity;
        totalCosmos += s->cosmos;
        totalFirmament += s->firmament;
        totalAether += s->aether;
    }
    
    int eternalCount = 0;
    for (auto& e : s_eternityCelestials) {
        if (e->isEternal) eternalCount++;
    }
    
    int vaultedCount = 0;
    for (auto& f : s_firmamentCelestials) {
        if (f->isVaulted) vaultedCount++;
    }
    
    return {
        {"celestialStructureCount", s_celestialStructures.size()},
        {"eternityCelestialCount", s_eternityCelestials.size()},
        {"cosmosCelestialCount", s_cosmosCelestials.size()},
        {"firmamentCelestialCount", s_firmamentCelestials.size()},
        {"aetherCelestialCount", s_aetherCelestials.size()},
        {"totalCelestialness", totalCelestialness},
        {"totalEternity", totalEternity},
        {"totalCosmos", totalCosmos},
        {"totalFirmament", totalFirmament},
        {"totalAether", totalAether},
        {"eternalCount", eternalCount},
        {"vaultedCount", vaultedCount}
    };
}

nlohmann::json CelestialEternityEngine::GenerateCelestialEternityReport() {
    auto report = GetCelestialEternityMetrics();
    
    std::lock_guard<std::mutex> lock(s_celestialMutex);
    nlohmann::json structures = nlohmann::json::array();
    for (auto& s : s_celestialStructures) {
        structures.push_back(s->ToJson());
    }
    report["structures"] = structures;
    
    return report;
}

} // namespace CelestialEternity
