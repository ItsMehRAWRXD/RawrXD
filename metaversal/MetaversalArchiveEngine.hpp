#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>

namespace Metaversal {

struct UniversalHistory {
    std::string historyId;
    std::string title;
    std::string description;
    std::string universeId;
    nlohmann::json timeline;
    float significanceScore;
    int64_t recordedTimestamp;
};

struct CosmicRecord {
    std::string recordId;
    std::string name;
    std::string recordType; // "event", "entity", "artifact", "phenomenon"
    nlohmann::json data;
    std::vector<std::string> tags;
    float preservationPriority;
    int64_t archivedTimestamp;
};

struct MultiversalLibrary {
    std::string libraryId;
    std::string name;
    std::string description;
    std::vector<std::string> universesServed;
    std::map<std::string, std::string> collections;
    float accessLevel;
    int64_t establishedTimestamp;
};

struct OmniversalDocument {
    std::string documentId;
    std::string title;
    std::string author;
    std::string classification; // "public", "restricted", "classified", "omniversal"
    nlohmann::json content;
    std::vector<std::string> universesAccessible;
    int64_t createdTimestamp;
    int64_t modifiedTimestamp;
};

struct ArchiveIndex {
    std::string indexId;
    std::string name;
    std::string indexType;
    std::map<std::string, std::vector<std::string>> entries;
    float completenessScore;
    int64_t lastUpdatedTimestamp;
};

class MetaversalArchiveEngine {
public:
    static void Init();
    static void Shutdown();
    
    static std::string RecordUniversalHistory(const std::string& title,
                                              const std::string& description,
                                              const std::string& universeId,
                                              const nlohmann::json& timeline);
    static bool UpdateHistory(const std::string& historyId, const nlohmann::json& updates);
    static UniversalHistory GetHistory(const std::string& historyId);
    static std::vector<UniversalHistory> GetAllHistories();
    static std::vector<UniversalHistory> GetHistoriesByUniverse(const std::string& universeId);
    
    static std::string ArchiveCosmicRecord(const std::string& name,
                                          const std::string& recordType,
                                          const nlohmann::json& data,
                                          const std::vector<std::string>& tags);
    static bool UpdateRecord(const std::string& recordId, const nlohmann::json& updates);
    static bool DeleteRecord(const std::string& recordId);
    static CosmicRecord GetRecord(const std::string& recordId);
    static std::vector<CosmicRecord> GetAllRecords();
    static std::vector<CosmicRecord> GetRecordsByType(const std::string& recordType);
    static std::vector<CosmicRecord> SearchRecordsByTag(const std::string& tag);
    
    static std::string EstablishMultiversalLibrary(const std::string& name,
                                                   const std::string& description,
                                                   const std::vector<std::string>& universes);
    static bool AddCollectionToLibrary(const std::string& libraryId, 
                                       const std::string& collectionName,
                                       const std::string& collectionId);
    static MultiversalLibrary GetLibrary(const std::string& libraryId);
    static std::vector<MultiversalLibrary> GetAllLibraries();
    
    static std::string CreateOmniversalDocument(const std::string& title,
                                                 const std::string& author,
                                                 const std::string& classification,
                                                 const nlohmann::json& content,
                                                 const std::vector<std::string>& universes);
    static bool UpdateDocument(const std::string& documentId, const nlohmann::json& updates);
    static bool ClassifyDocument(const std::string& documentId, const std::string& newClassification);
    static OmniversalDocument GetDocument(const std::string& documentId);
    static std::vector<OmniversalDocument> GetAllDocuments();
    static std::vector<OmniversalDocument> GetDocumentsByClassification(const std::string& classification);
    
    static std::string CreateArchiveIndex(const std::string& name,
                                         const std::string& indexType);
    static bool IndexEntry(const std::string& indexId, 
                          const std::string& key,
                          const std::string& entryId);
    static std::vector<std::string> SearchIndex(const std::string& indexId, const std::string& key);
    static ArchiveIndex GetIndex(const std::string& indexId);
    
    static float CalculateArchiveCompleteness();
    static float CalculatePreservationIndex();
    static nlohmann::json GetArchiveMetrics();
    static nlohmann::json GenerateArchiveReport();
    
    static void OnTick();
    static bool IsAlive();

private:
    static std::mutex s_mutex;
    static bool s_initialized;
    static std::map<std::string, UniversalHistory> s_histories;
    static std::map<std::string, CosmicRecord> s_records;
    static std::map<std::string, MultiversalLibrary> s_libraries;
    static std::map<std::string, OmniversalDocument> s_documents;
    static std::map<std::string, ArchiveIndex> s_indices;
    static int64_t s_tickCount;
};

} // namespace Metaversal
