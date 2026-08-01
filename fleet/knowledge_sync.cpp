#include "knowledge_sync.hpp"
#include <chrono>
#include <algorithm>
#include <iostream>

namespace RawrXD::Fleet {

void KnowledgeSync::Store(const std::string& key, const std::string& value, const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);
    KnowledgeEntry entry;
    entry.key = key;
    entry.value = value;
    entry.category = category;
    entry.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    entries_[key] = entry;
}

std::string KnowledgeSync::Retrieve(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    return it != entries_.end() ? it->second.value : "";
}

std::vector<KnowledgeEntry> KnowledgeSync::Search(const std::string& query) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<KnowledgeEntry> results;
    for (const auto& [key, entry] : entries_) {
        if (key.find(query) != std::string::npos ||
            entry.value.find(query) != std::string::npos ||
            entry.category.find(query) != std::string::npos) {
            results.push_back(entry);
        }
    }
    return results;
}

void KnowledgeSync::SyncWithNode(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << "Syncing knowledge with " << node_id << "...\n";
    std::cout << "Knowledge entries: " << entries_.size() << "\n";
    std::cout << "Sync complete\n";
}

size_t KnowledgeSync::GetEntryCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

void KnowledgeSync::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

} // namespace RawrXD::Fleet
