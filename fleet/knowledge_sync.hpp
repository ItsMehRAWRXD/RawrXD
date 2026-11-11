#pragma once
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>

namespace RawrXD::Fleet {

struct KnowledgeEntry {
    std::string key;
    std::string value;
    std::string category;
    int64_t timestamp = 0;
    std::string source_node;
};

class KnowledgeSync {
public:
    KnowledgeSync() = default;
    ~KnowledgeSync() = default;

    void Store(const std::string& key, const std::string& value, const std::string& category = "general");
    std::string Retrieve(const std::string& key) const;
    std::vector<KnowledgeEntry> Search(const std::string& query) const;
    void SyncWithNode(const std::string& node_id);
    size_t GetEntryCount() const;
    void Clear();

private:
    std::map<std::string, KnowledgeEntry> entries_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Fleet
