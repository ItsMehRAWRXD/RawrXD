#include "eternal/EternalSanctuaryEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Eternal {

std::mutex EternalSanctuaryEngine::s_mutex;
bool EternalSanctuaryEngine::s_initialized = false;
std::map<std::string, UniversalVault> EternalSanctuaryEngine::s_vaults;
std::map<std::string, CosmicPreserve> EternalSanctuaryEngine::s_preserves;
std::map<std::string, MultiversalSanctuary> EternalSanctuaryEngine::s_sanctuaries;
std::map<std::string, TranscendentRepository> EternalSanctuaryEngine::s_repositories;
std::map<std::string, SanctuaryRefugee> EternalSanctuaryEngine::s_refugees;
int64_t EternalSanctuaryEngine::s_tickCount = 0;

void EternalSanctuaryEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void EternalSanctuaryEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_vaults.clear();
    s_preserves.clear();
    s_sanctuaries.clear();
    s_repositories.clear();
    s_refugees.clear();
}

std::string EternalSanctuaryEngine::EstablishUniversalVault(const std::string& name,
                                                           const std::string& vaultType,
                                                           float capacity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int vaultCounter = 0;
    std::string vaultId = "universal_vault_" + std::to_string(++vaultCounter);
    
    UniversalVault vault;
    vault.vaultId = vaultId;
    vault.name = name;
    vault.vaultType = vaultType;
    vault.capacity = capacity;
    vault.currentLoad = 0.0f;
    vault.preservationLevel = 1.0f;
    vault.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_vaults[vaultId] = vault;
    return vaultId;
}

bool EternalSanctuaryEngine::StoreInVault(const std::string& vaultId, 
                                          const std::string& itemId, 
                                          float amount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vaults.find(vaultId);
    if (it == s_vaults.end()) return false;
    if (it->second.currentLoad + amount > it->second.capacity) return false;
    it->second.contents[itemId] += amount;
    it->second.currentLoad += amount;
    return true;
}

bool EternalSanctuaryEngine::RetrieveFromVault(const std::string& vaultId, 
                                               const std::string& itemId, 
                                               float amount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vaults.find(vaultId);
    if (it == s_vaults.end()) return false;
    auto itemIt = it->second.contents.find(itemId);
    if (itemIt == it->second.contents.end() || itemIt->second < amount) return false;
    itemIt->second -= amount;
    it->second.currentLoad -= amount;
    if (itemIt->second <= 0) it->second.contents.erase(itemIt);
    return true;
}

bool EternalSanctuaryEngine::UpgradeVaultCapacity(const std::string& vaultId, float additionalCapacity) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vaults.find(vaultId);
    if (it == s_vaults.end()) return false;
    it->second.capacity += additionalCapacity;
    return true;
}

UniversalVault EternalSanctuaryEngine::GetVault(const std::string& vaultId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_vaults.find(vaultId);
    if (it != s_vaults.end()) return it->second;
    return UniversalVault{};
}

std::vector<UniversalVault> EternalSanctuaryEngine::GetAllVaults() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalVault> result;
    for (const auto& [id, vault] : s_vaults) {
        result.push_back(vault);
    }
    return result;
}

std::vector<UniversalVault> EternalSanctuaryEngine::GetVaultsByType(const std::string& vaultType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalVault> result;
    for (const auto& [id, vault] : s_vaults) {
        if (vault.vaultType == vaultType) result.push_back(vault);
    }
    return result;
}

std::string EternalSanctuaryEngine::DesignateCosmicPreserve(const std::string& name,
                                                              const std::string& preserveType,
                                                              const std::vector<std::string>& entities) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int preserveCounter = 0;
    std::string preserveId = "cosmic_preserve_" + std::to_string(++preserveCounter);
    
    CosmicPreserve preserve;
    preserve.preserveId = preserveId;
    preserve.name = name;
    preserve.preserveType = preserveType;
    preserve.protectedEntities = entities;
    preserve.vitalityIndex = 1.0f;
    preserve.sustainabilityScore = 1.0f;
    preserve.designatedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_preserves[preserveId] = preserve;
    return preserveId;
}

bool EternalSanctuaryEngine::AddEntityToPreserve(const std::string& preserveId, const std::string& entityId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_preserves.find(preserveId);
    if (it == s_preserves.end()) return false;
    it->second.protectedEntities.push_back(entityId);
    return true;
}

bool EternalSanctuaryEngine::RemoveEntityFromPreserve(const std::string& preserveId, const std::string& entityId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_preserves.find(preserveId);
    if (it == s_preserves.end()) return false;
    auto& entities = it->second.protectedEntities;
    entities.erase(std::remove(entities.begin(), entities.end(), entityId), entities.end());
    return true;
}

bool EternalSanctuaryEngine::NourishPreserve(const std::string& preserveId, float vitalityBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_preserves.find(preserveId);
    if (it == s_preserves.end()) return false;
    it->second.vitalityIndex = std::min(1.0f, it->second.vitalityIndex + vitalityBoost);
    return true;
}

CosmicPreserve EternalSanctuaryEngine::GetPreserve(const std::string& preserveId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_preserves.find(preserveId);
    if (it != s_preserves.end()) return it->second;
    return CosmicPreserve{};
}

std::vector<CosmicPreserve> EternalSanctuaryEngine::GetAllPreserves() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicPreserve> result;
    for (const auto& [id, preserve] : s_preserves) {
        result.push_back(preserve);
    }
    return result;
}

std::vector<CosmicPreserve> EternalSanctuaryEngine::GetPreservesByType(const std::string& preserveType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicPreserve> result;
    for (const auto& [id, preserve] : s_preserves) {
        if (preserve.preserveType == preserveType) result.push_back(preserve);
    }
    return result;
}

std::string EternalSanctuaryEngine::ConsecrateMultiversalSanctuary(const std::string& name,
                                                                   const std::string& sanctuaryClass,
                                                                   const std::vector<std::string>& universes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int sanctuaryCounter = 0;
    std::string sanctuaryId = "multiversal_sanctuary_" + std::to_string(++sanctuaryCounter);
    
    MultiversalSanctuary sanctuary;
    sanctuary.sanctuaryId = sanctuaryId;
    sanctuary.name = name;
    sanctuary.sanctuaryClass = sanctuaryClass;
    sanctuary.protectedUniverses = universes;
    sanctuary.defenseCapability = 1.0f;
    sanctuary.resourceReserves = 1.0f;
    sanctuary.consecratedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_sanctuaries[sanctuaryId] = sanctuary;
    return sanctuaryId;
}

bool EternalSanctuaryEngine::FortifySanctuary(const std::string& sanctuaryId, float defenseBoost) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_sanctuaries.find(sanctuaryId);
    if (it == s_sanctuaries.end()) return false;
    it->second.defenseCapability = std::min(1.0f, it->second.defenseCapability + defenseBoost);
    return true;
}

bool EternalSanctuaryEngine::StockSanctuaryResources(const std::string& sanctuaryId, float resourceAmount) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_sanctuaries.find(sanctuaryId);
    if (it == s_sanctuaries.end()) return false;
    it->second.resourceReserves = std::min(1.0f, it->second.resourceReserves + resourceAmount);
    return true;
}

bool EternalSanctuaryEngine::AdmitRefugeeToSanctuary(const std::string& sanctuaryId, const std::string& refugeeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto sanctIt = s_sanctuaries.find(sanctuaryId);
    auto refIt = s_refugees.find(refugeeId);
    if (sanctIt == s_sanctuaries.end() || refIt == s_refugees.end()) return false;
    refIt->second.currentSanctuary = sanctuaryId;
    refIt->second.status = "resettled";
    return true;
}

MultiversalSanctuary EternalSanctuaryEngine::GetSanctuary(const std::string& sanctuaryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_sanctuaries.find(sanctuaryId);
    if (it != s_sanctuaries.end()) return it->second;
    return MultiversalSanctuary{};
}

std::vector<MultiversalSanctuary> EternalSanctuaryEngine::GetAllSanctuaries() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalSanctuary> result;
    for (const auto& [id, sanctuary] : s_sanctuaries) {
        result.push_back(sanctuary);
    }
    return result;
}

std::vector<MultiversalSanctuary> EternalSanctuaryEngine::GetSanctuariesByClass(const std::string& sanctuaryClass) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalSanctuary> result;
    for (const auto& [id, sanctuary] : s_sanctuaries) {
        if (sanctuary.sanctuaryClass == sanctuaryClass) result.push_back(sanctuary);
    }
    return result;
}

std::string EternalSanctuaryEngine::FoundTranscendentRepository(const std::string& name,
                                                                const std::string& repositoryType,
                                                                const nlohmann::json& initialData) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int repositoryCounter = 0;
    std::string repositoryId = "transcendent_repo_" + std::to_string(++repositoryCounter);
    
    TranscendentRepository repository;
    repository.repositoryId = repositoryId;
    repository.name = name;
    repository.repositoryType = repositoryType;
    repository.repositoryData = initialData;
    repository.integrityLevel = 1.0f;
    repository.accessibilityIndex = 1.0f;
    repository.foundedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_repositories[repositoryId] = repository;
    return repositoryId;
}

bool EternalSanctuaryEngine::ArchiveInRepository(const std::string& repositoryId, 
                                                 const std::string& entryId,
                                                 const nlohmann::json& data) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_repositories.find(repositoryId);
    if (it == s_repositories.end()) return false;
    it->second.repositoryData[entryId] = data;
    return true;
}

bool EternalSanctuaryEngine::RestoreFromRepository(const std::string& repositoryId, const std::string& entryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_repositories.find(repositoryId);
    if (it == s_repositories.end()) return false;
    it->second.repositoryData.erase(entryId);
    return true;
}

bool EternalSanctuaryEngine::MaintainRepositoryIntegrity(const std::string& repositoryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_repositories.find(repositoryId);
    if (it == s_repositories.end()) return false;
    it->second.integrityLevel = 1.0f;
    return true;
}

TranscendentRepository EternalSanctuaryEngine::GetRepository(const std::string& repositoryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_repositories.find(repositoryId);
    if (it != s_repositories.end()) return it->second;
    return TranscendentRepository{};
}

std::vector<TranscendentRepository> EternalSanctuaryEngine::GetAllRepositories() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentRepository> result;
    for (const auto& [id, repository] : s_repositories) {
        result.push_back(repository);
    }
    return result;
}

std::vector<TranscendentRepository> EternalSanctuaryEngine::GetRepositoriesByType(const std::string& repositoryType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<TranscendentRepository> result;
    for (const auto& [id, repository] : s_repositories) {
        if (repository.repositoryType == repositoryType) result.push_back(repository);
    }
    return result;
}

std::string EternalSanctuaryEngine::RegisterSanctuaryRefugee(const std::string& name,
                                                             const std::string& originUniverse) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int refugeeCounter = 0;
    std::string refugeeId = "sanctuary_refugee_" + std::to_string(++refugeeCounter);
    
    SanctuaryRefugee refugee;
    refugee.refugeeId = refugeeId;
    refugee.name = name;
    refugee.originUniverse = originUniverse;
    refugee.currentSanctuary = "";
    refugee.status = "seeking";
    refugee.arrivalTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_refugees[refugeeId] = refugee;
    return refugeeId;
}

bool EternalSanctuaryEngine::UpdateRefugeeStatus(const std::string& refugeeId, const std::string& newStatus) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_refugees.find(refugeeId);
    if (it == s_refugees.end()) return false;
    it->second.status = newStatus;
    return true;
}

bool EternalSanctuaryEngine::RelocateRefugee(const std::string& refugeeId, const std::string& newSanctuary) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_refugees.find(refugeeId);
    if (it == s_refugees.end()) return false;
    it->second.currentSanctuary = newSanctuary;
    return true;
}

SanctuaryRefugee EternalSanctuaryEngine::GetRefugee(const std::string& refugeeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_refugees.find(refugeeId);
    if (it != s_refugees.end()) return it->second;
    return SanctuaryRefugee{};
}

std::vector<SanctuaryRefugee> EternalSanctuaryEngine::GetAllRefugees() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<SanctuaryRefugee> result;
    for (const auto& [id, refugee] : s_refugees) {
        result.push_back(refugee);
    }
    return result;
}

std::vector<SanctuaryRefugee> EternalSanctuaryEngine::GetRefugeesByStatus(const std::string& status) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<SanctuaryRefugee> result;
    for (const auto& [id, refugee] : s_refugees) {
        if (refugee.status == status) result.push_back(refugee);
    }
    return result;
}

float EternalSanctuaryEngine::CalculateTotalPreservationCapacity() {
    std::lock_guard<std::mutex> lock(s_mutex);
    float totalCapacity = 0.0f;
    for (const auto& [id, vault] : s_vaults) {
        totalCapacity += vault.capacity;
    }
    for (const auto& [id, preserve] : s_preserves) {
        totalCapacity += preserve.vitalityIndex * 100.0f;
    }
    return totalCapacity;
}

float EternalSanctuaryEngine::CalculateSanctuarySecurityIndex() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_sanctuaries.empty()) return 1.0f;
    float totalSecurity = 0.0f;
    for (const auto& [id, sanctuary] : s_sanctuaries) {
        totalSecurity += sanctuary.defenseCapability;
    }
    return totalSecurity / s_sanctuaries.size();
}

nlohmann::json EternalSanctuaryEngine::GetSanctuaryMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["vaultCount"] = s_vaults.size();
    metrics["preserveCount"] = s_preserves.size();
    metrics["sanctuaryCount"] = s_sanctuaries.size();
    metrics["repositoryCount"] = s_repositories.size();
    metrics["refugeeCount"] = s_refugees.size();
    metrics["totalPreservationCapacity"] = CalculateTotalPreservationCapacity();
    metrics["sanctuarySecurityIndex"] = CalculateSanctuarySecurityIndex();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json EternalSanctuaryEngine::GenerateSanctuaryReport() {
    nlohmann::json report;
    report["metrics"] = GetSanctuaryMetrics();
    report["establishedVaults"] = nlohmann::json::array();
    report["designatedPreserves"] = nlohmann::json::array();
    report["consecratedSanctuaries"] = nlohmann::json::array();
    
    for (const auto& vault : GetAllVaults()) {
        nlohmann::json v;
        v["id"] = vault.vaultId;
        v["name"] = vault.name;
        v["type"] = vault.vaultType;
        v["capacity"] = vault.capacity;
        v["load"] = vault.currentLoad;
        report["establishedVaults"].push_back(v);
    }
    
    for (const auto& preserve : GetAllPreserves()) {
        nlohmann::json p;
        p["id"] = preserve.preserveId;
        p["name"] = preserve.name;
        p["type"] = preserve.preserveType;
        p["vitality"] = preserve.vitalityIndex;
        report["designatedPreserves"].push_back(p);
    }
    
    for (const auto& sanctuary : GetAllSanctuaries()) {
        nlohmann::json s;
        s["id"] = sanctuary.sanctuaryId;
        s["name"] = sanctuary.name;
        s["class"] = sanctuary.sanctuaryClass;
        s["defense"] = sanctuary.defenseCapability;
        report["consecratedSanctuaries"].push_back(s);
    }
    
    return report;
}

void EternalSanctuaryEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, vault] : s_vaults) {
        vault.preservationLevel *= 0.9999f;
        vault.preservationLevel += 0.0001f;
    }
    
    for (auto& [id, preserve] : s_preserves) {
        preserve.vitalityIndex *= 0.9999f;
        preserve.vitalityIndex += 0.0001f;
        preserve.sustainabilityScore *= 0.9999f;
        preserve.sustainabilityScore += 0.0001f;
    }
    
    for (auto& [id, sanctuary] : s_sanctuaries) {
        sanctuary.defenseCapability *= 0.9999f;
        sanctuary.defenseCapability += 0.0001f;
    }
    
    for (auto& [id, repository] : s_repositories) {
        repository.integrityLevel *= 0.9999f;
        repository.integrityLevel += 0.0001f;
    }
}

bool EternalSanctuaryEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Eternal
