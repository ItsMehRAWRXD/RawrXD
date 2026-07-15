#include "metaversal/MetaversalArchiveEngine.hpp"
#include <chrono>
#include <algorithm>

namespace Metaversal {

std::mutex MetaversalArchiveEngine::s_mutex;
bool MetaversalArchiveEngine::s_initialized = false;
std::map<std::string, UniversalHistory> MetaversalArchiveEngine::s_histories;
std::map<std::string, CosmicRecord> MetaversalArchiveEngine::s_records;
std::map<std::string, MultiversalLibrary> MetaversalArchiveEngine::s_libraries;
std::map<std::string, OmniversalDocument> MetaversalArchiveEngine::s_documents;
std::map<std::string, ArchiveIndex> MetaversalArchiveEngine::s_indices;
int64_t MetaversalArchiveEngine::s_tickCount = 0;

void MetaversalArchiveEngine::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_initialized) return;
    s_initialized = true;
    s_tickCount = 0;
}

void MetaversalArchiveEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = false;
    s_histories.clear();
    s_records.clear();
    s_libraries.clear();
    s_documents.clear();
    s_indices.clear();
}

std::string MetaversalArchiveEngine::RecordUniversalHistory(const std::string& title,
                                                           const std::string& description,
                                                           const std::string& universeId,
                                                           const nlohmann::json& timeline) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int historyCounter = 0;
    std::string historyId = "universal_history_" + std::to_string(++historyCounter);
    
    UniversalHistory history;
    history.historyId = historyId;
    history.title = title;
    history.description = description;
    history.universeId = universeId;
    history.timeline = timeline;
    history.significanceScore = 1.0f;
    history.recordedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_histories[historyId] = history;
    return historyId;
}

bool MetaversalArchiveEngine::UpdateHistory(const std::string& historyId, const nlohmann::json& updates) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_histories.find(historyId);
    if (it == s_histories.end()) return false;
    if (updates.contains("title")) it->second.title = updates["title"];
    if (updates.contains("description")) it->second.description = updates["description"];
    if (updates.contains("timeline")) it->second.timeline = updates["timeline"];
    return true;
}

UniversalHistory MetaversalArchiveEngine::GetHistory(const std::string& historyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_histories.find(historyId);
    if (it != s_histories.end()) return it->second;
    return UniversalHistory{};
}

std::vector<UniversalHistory> MetaversalArchiveEngine::GetAllHistories() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalHistory> result;
    for (const auto& [id, history] : s_histories) {
        result.push_back(history);
    }
    return result;
}

std::vector<UniversalHistory> MetaversalArchiveEngine::GetHistoriesByUniverse(const std::string& universeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<UniversalHistory> result;
    for (const auto& [id, history] : s_histories) {
        if (history.universeId == universeId) result.push_back(history);
    }
    return result;
}

std::string MetaversalArchiveEngine::ArchiveCosmicRecord(const std::string& name,
                                                         const std::string& recordType,
                                                         const nlohmann::json& data,
                                                         const std::vector<std::string>& tags) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int recordCounter = 0;
    std::string recordId = "cosmic_record_" + std::to_string(++recordCounter);
    
    CosmicRecord record;
    record.recordId = recordId;
    record.name = name;
    record.recordType = recordType;
    record.data = data;
    record.tags = tags;
    record.preservationPriority = 1.0f;
    record.archivedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_records[recordId] = record;
    return recordId;
}

bool MetaversalArchiveEngine::UpdateRecord(const std::string& recordId, const nlohmann::json& updates) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_records.find(recordId);
    if (it == s_records.end()) return false;
    if (updates.contains("name")) it->second.name = updates["name"];
    if (updates.contains("data")) it->second.data = updates["data"];
    if (updates.contains("tags")) it->second.tags = updates["tags"].get<std::vector<std::string>>();
    return true;
}

bool MetaversalArchiveEngine::DeleteRecord(const std::string& recordId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_records.find(recordId);
    if (it == s_records.end()) return false;
    s_records.erase(it);
    return true;
}

CosmicRecord MetaversalArchiveEngine::GetRecord(const std::string& recordId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_records.find(recordId);
    if (it != s_records.end()) return it->second;
    return CosmicRecord{};
}

std::vector<CosmicRecord> MetaversalArchiveEngine::GetAllRecords() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicRecord> result;
    for (const auto& [id, record] : s_records) {
        result.push_back(record);
    }
    return result;
}

std::vector<CosmicRecord> MetaversalArchiveEngine::GetRecordsByType(const std::string& recordType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicRecord> result;
    for (const auto& [id, record] : s_records) {
        if (record.recordType == recordType) result.push_back(record);
    }
    return result;
}

std::vector<CosmicRecord> MetaversalArchiveEngine::SearchRecordsByTag(const std::string& tag) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<CosmicRecord> result;
    for (const auto& [id, record] : s_records) {
        if (std::find(record.tags.begin(), record.tags.end(), tag) != record.tags.end()) {
            result.push_back(record);
        }
    }
    return result;
}

std::string MetaversalArchiveEngine::EstablishMultiversalLibrary(const std::string& name,
                                                                   const std::string& description,
                                                                   const std::vector<std::string>& universes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int libraryCounter = 0;
    std::string libraryId = "multiversal_library_" + std::to_string(++libraryCounter);
    
    MultiversalLibrary library;
    library.libraryId = libraryId;
    library.name = name;
    library.description = description;
    library.universesServed = universes;
    library.accessLevel = 1.0f;
    library.establishedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_libraries[libraryId] = library;
    return libraryId;
}

bool MetaversalArchiveEngine::AddCollectionToLibrary(const std::string& libraryId, 
                                                     const std::string& collectionName,
                                                     const std::string& collectionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_libraries.find(libraryId);
    if (it == s_libraries.end()) return false;
    it->second.collections[collectionName] = collectionId;
    return true;
}

MultiversalLibrary MetaversalArchiveEngine::GetLibrary(const std::string& libraryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_libraries.find(libraryId);
    if (it != s_libraries.end()) return it->second;
    return MultiversalLibrary{};
}

std::vector<MultiversalLibrary> MetaversalArchiveEngine::GetAllLibraries() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<MultiversalLibrary> result;
    for (const auto& [id, library] : s_libraries) {
        result.push_back(library);
    }
    return result;
}

std::string MetaversalArchiveEngine::CreateOmniversalDocument(const std::string& title,
                                                              const std::string& author,
                                                              const std::string& classification,
                                                              const nlohmann::json& content,
                                                              const std::vector<std::string>& universes) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int documentCounter = 0;
    std::string documentId = "omniversal_doc_" + std::to_string(++documentCounter);
    
    OmniversalDocument document;
    document.documentId = documentId;
    document.title = title;
    document.author = author;
    document.classification = classification;
    document.content = content;
    document.universesAccessible = universes;
    document.createdTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    document.modifiedTimestamp = document.createdTimestamp;
    
    s_documents[documentId] = document;
    return documentId;
}

bool MetaversalArchiveEngine::UpdateDocument(const std::string& documentId, const nlohmann::json& updates) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_documents.find(documentId);
    if (it == s_documents.end()) return false;
    if (updates.contains("title")) it->second.title = updates["title"];
    if (updates.contains("content")) it->second.content = updates["content"];
    it->second.modifiedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

bool MetaversalArchiveEngine::ClassifyDocument(const std::string& documentId, const std::string& newClassification) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_documents.find(documentId);
    if (it == s_documents.end()) return false;
    it->second.classification = newClassification;
    it->second.modifiedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

OmniversalDocument MetaversalArchiveEngine::GetDocument(const std::string& documentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_documents.find(documentId);
    if (it != s_documents.end()) return it->second;
    return OmniversalDocument{};
}

std::vector<OmniversalDocument> MetaversalArchiveEngine::GetAllDocuments() {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<OmniversalDocument> result;
    for (const auto& [id, document] : s_documents) {
        result.push_back(document);
    }
    return result;
}

std::vector<OmniversalDocument> MetaversalArchiveEngine::GetDocumentsByClassification(const std::string& classification) {
    std::lock_guard<std::mutex> lock(s_mutex);
    std::vector<OmniversalDocument> result;
    for (const auto& [id, document] : s_documents) {
        if (document.classification == classification) result.push_back(document);
    }
    return result;
}

std::string MetaversalArchiveEngine::CreateArchiveIndex(const std::string& name,
                                                         const std::string& indexType) {
    std::lock_guard<std::mutex> lock(s_mutex);
    static int indexCounter = 0;
    std::string indexId = "archive_index_" + std::to_string(++indexCounter);
    
    ArchiveIndex index;
    index.indexId = indexId;
    index.name = name;
    index.indexType = indexType;
    index.completenessScore = 1.0f;
    index.lastUpdatedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    s_indices[indexId] = index;
    return indexId;
}

bool MetaversalArchiveEngine::IndexEntry(const std::string& indexId, 
                                        const std::string& key,
                                        const std::string& entryId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_indices.find(indexId);
    if (it == s_indices.end()) return false;
    it->second.entries[key].push_back(entryId);
    it->second.lastUpdatedTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

std::vector<std::string> MetaversalArchiveEngine::SearchIndex(const std::string& indexId, const std::string& key) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_indices.find(indexId);
    if (it == s_indices.end()) return {};
    auto entryIt = it->second.entries.find(key);
    if (entryIt != it->second.entries.end()) return entryIt->second;
    return {};
}

ArchiveIndex MetaversalArchiveEngine::GetIndex(const std::string& indexId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_indices.find(indexId);
    if (it != s_indices.end()) return it->second;
    return ArchiveIndex{};
}

float MetaversalArchiveEngine::CalculateArchiveCompleteness() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_indices.empty()) return 1.0f;
    float totalCompleteness = 0.0f;
    for (const auto& [id, index] : s_indices) {
        totalCompleteness += index.completenessScore;
    }
    return totalCompleteness / s_indices.size();
}

float MetaversalArchiveEngine::CalculatePreservationIndex() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (s_records.empty()) return 1.0f;
    float totalPriority = 0.0f;
    for (const auto& [id, record] : s_records) {
        totalPriority += record.preservationPriority;
    }
    return totalPriority / s_records.size();
}

nlohmann::json MetaversalArchiveEngine::GetArchiveMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json metrics;
    metrics["historyCount"] = s_histories.size();
    metrics["recordCount"] = s_records.size();
    metrics["libraryCount"] = s_libraries.size();
    metrics["documentCount"] = s_documents.size();
    metrics["indexCount"] = s_indices.size();
    metrics["archiveCompleteness"] = CalculateArchiveCompleteness();
    metrics["preservationIndex"] = CalculatePreservationIndex();
    metrics["tickCount"] = s_tickCount;
    return metrics;
}

nlohmann::json MetaversalArchiveEngine::GenerateArchiveReport() {
    nlohmann::json report;
    report["metrics"] = GetArchiveMetrics();
    report["recentHistories"] = nlohmann::json::array();
    report["preservedRecords"] = nlohmann::json::array();
    report["activeLibraries"] = nlohmann::json::array();
    
    for (const auto& history : GetAllHistories()) {
        nlohmann::json h;
        h["id"] = history.historyId;
        h["title"] = history.title;
        h["universe"] = history.universeId;
        h["significance"] = history.significanceScore;
        report["recentHistories"].push_back(h);
    }
    
    for (const auto& record : GetAllRecords()) {
        nlohmann::json r;
        r["id"] = record.recordId;
        r["name"] = record.name;
        r["type"] = record.recordType;
        r["priority"] = record.preservationPriority;
        report["preservedRecords"].push_back(r);
    }
    
    return report;
}

void MetaversalArchiveEngine::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_tickCount++;
    
    for (auto& [id, history] : s_histories) {
        history.significanceScore *= 0.9999f;
        history.significanceScore += 0.0001f;
    }
    
    for (auto& [id, record] : s_records) {
        record.preservationPriority *= 0.9999f;
        record.preservationPriority += 0.0001f;
    }
}

bool MetaversalArchiveEngine::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

} // namespace Metaversal
