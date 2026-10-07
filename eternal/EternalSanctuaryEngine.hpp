#pragma once
#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Eternal {

struct UniversalVault {
    std::string vaultId;
    std::string name;
    std::string vaultType; // "matter", "energy", "knowledge", "essence"
    float capacity;
    float currentLoad;
    std::map<std::string, float> contents;
    float preservationLevel;
    int64_t establishedTimestamp;
};

struct CosmicPreserve {
    std::string preserveId;
    std::string name;
    std::string preserveType; // "ecosystem", "species", "culture", "technology"
    std::vector<std::string> protectedEntities;
    float vitalityIndex;
    float sustainabilityScore;
    int64_t designatedTimestamp;
};

struct MultiversalSanctuary {
    std::string sanctuaryId;
    std::string name;
    std::string sanctuaryClass; // "refuge", "haven", "stronghold", "citadel"
    std::vector<std::string> protectedUniverses;
    float defenseCapability;
    float resourceReserves;
    int64_t consecratedTimestamp;
};

struct TranscendentRepository {
    std::string repositoryId;
    std::string name;
    std::string repositoryType; // "knowledge", "wisdom", "memory", "soul"
    nlohmann::json repositoryData;
    float integrityLevel;
    float accessibilityIndex;
    int64_t foundedTimestamp;
};

struct SanctuaryRefugee {
    std::string refugeeId;
    std::string name;
    std::string originUniverse;
    std::string currentSanctuary;
    std::string status; // "seeking", "resettled", "integrated", "departed"
    int64_t arrivalTimestamp;
};

class EternalSanctuaryEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string EstablishUniversalVault(const std::string& name,
                                               const std::string& vaultType,
                                               float capacity);
    static bool StoreInVault(const std::string& vaultId, 
                             const std::string& itemId, 
                             float amount);
    static bool RetrieveFromVault(const std::string& vaultId, 
                                  const std::string& itemId, 
                                  float amount);
    static bool UpgradeVaultCapacity(const std::string& vaultId, float additionalCapacity);
    static UniversalVault GetVault(const std::string& vaultId);
    static std::vector<UniversalVault> GetAllVaults();
    static std::vector<UniversalVault> GetVaultsByType(const std::string& vaultType);
    
    static std::string DesignateCosmicPreserve(const std::string& name,
                                               const std::string& preserveType,
                                               const std::vector<std::string>& entities);
    static bool AddEntityToPreserve(const std::string& preserveId, const std::string& entityId);
    static bool RemoveEntityFromPreserve(const std::string& preserveId, const std::string& entityId);
    static bool NourishPreserve(const std::string& preserveId, float vitalityBoost);
    static CosmicPreserve GetPreserve(const std::string& preserveId);
    static std::vector<CosmicPreserve> GetAllPreserves();
    static std::vector<CosmicPreserve> GetPreservesByType(const std::string& preserveType);
    
    static std::string ConsecrateMultiversalSanctuary(const std::string& name,
                                                      const std::string& sanctuaryClass,
                                                      const std::vector<std::string>& universes);
    static bool FortifySanctuary(const std::string& sanctuaryId, float defenseBoost);
    static bool StockSanctuaryResources(const std::string& sanctuaryId, float resourceAmount);
    static bool AdmitRefugeeToSanctuary(const std::string& sanctuaryId, const std::string& refugeeId);
    static MultiversalSanctuary GetSanctuary(const std::string& sanctuaryId);
    static std::vector<MultiversalSanctuary> GetAllSanctuaries();
    static std::vector<MultiversalSanctuary> GetSanctuariesByClass(const std::string& sanctuaryClass);
    
    static std::string FoundTranscendentRepository(const std::string& name,
                                                   const std::string& repositoryType,
                                                   const nlohmann::json& initialData);
    static bool ArchiveInRepository(const std::string& repositoryId, 
                                      const std::string& entryId,
                                      const nlohmann::json& data);
    static bool RestoreFromRepository(const std::string& repositoryId, const std::string& entryId);
    static bool MaintainRepositoryIntegrity(const std::string& repositoryId);
    static TranscendentRepository GetRepository(const std::string& repositoryId);
    static std::vector<TranscendentRepository> GetAllRepositories();
    static std::vector<TranscendentRepository> GetRepositoriesByType(const std::string& repositoryType);
    
    static std::string RegisterSanctuaryRefugee(const std::string& name,
                                                const std::string& originUniverse);
    static bool UpdateRefugeeStatus(const std::string& refugeeId, const std::string& newStatus);
    static bool RelocateRefugee(const std::string& refugeeId, const std::string& newSanctuary);
    static SanctuaryRefugee GetRefugee(const std::string& refugeeId);
    static std::vector<SanctuaryRefugee> GetAllRefugees();
    static std::vector<SanctuaryRefugee> GetRefugeesByStatus(const std::string& status);
    
    static float CalculateTotalPreservationCapacity();
    static float CalculateSanctuarySecurityIndex();
    static nlohmann::json GetSanctuaryMetrics();
    static nlohmann::json GenerateSanctuaryReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, UniversalVault> s_vaults;
    static std::map<std::string, CosmicPreserve> s_preserves;
    static std::map<std::string, MultiversalSanctuary> s_sanctuaries;
    static std::map<std::string, TranscendentRepository> s_repositories;
    static std::map<std::string, SanctuaryRefugee> s_refugees;
    static int64_t s_tickCount;
};

} // namespace Eternal
