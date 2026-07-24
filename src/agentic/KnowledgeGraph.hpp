// ============================================================================
// KnowledgeGraph.hpp - Long-term memory for agents
// ============================================================================
#pragma once

#include "AgentTypes.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

namespace RawrXD::Agentic {

// ============================================================================
// Knowledge categories
// ============================================================================

struct KnowledgeCategory {
    std::string name;
    std::string description;
    size_t entry_count = 0;
};

// ============================================================================
// KnowledgeGraph - accumulates reusable knowledge across analyses
// ============================================================================

class KnowledgeGraph {
public:
    KnowledgeGraph() {
        // Initialize known categories
        categories_["compiler_signatures"] = {"compiler_signatures", "Known compiler signatures and patterns", 0};
        categories_["packers"] = {"packers", "Known packer signatures", 0};
        categories_["obfuscation_styles"] = {"obfuscation_styles", "Known obfuscation techniques", 0};
        categories_["malware_families"] = {"malware_families", "Known malware family signatures", 0};
        categories_["cfg_fragments"] = {"cfg_fragments", "Known control flow graph fragments", 0};
        categories_["import_patterns"] = {"import_patterns", "Known import patterns", 0};
        categories_["solved_binaries"] = {"solved_binaries", "Previously solved binaries", 0};
        categories_["pattern_signatures"] = {"pattern_signatures", "Discovered pattern signatures", 0};
        categories_["agent_workflows"] = {"agent_workflows", "Successful agent workflows", 0};
        categories_["anomaly_patterns"] = {"anomaly_patterns", "Known anomaly patterns", 0};
    }

    ~KnowledgeGraph() = default;

    // Add a knowledge entry
    void addEntry(const KnowledgeEntry& entry) {
        std::unique_lock lock(mutex_);
        std::string key = entry.category + "::" + entry.key;
        entries_[key] = entry;
        categories_[entry.category].entry_count++;
        total_entries_++;
    }

    // Add a simple key-value entry
    void addFact(const std::string& category, const std::string& key, 
                 const std::string& value, double confidence = 0.8) {
        KnowledgeEntry entry;
        entry.key = key;
        entry.value = value;
        entry.category = category;
        entry.confidence = confidence;
        entry.sources = {"agentic_platform"};
        entry.created = std::chrono::steady_clock::now();
        entry.last_accessed = entry.created;
        entry.access_count = 0;
        entry.verified = false;
        addEntry(entry);
    }

    // Query knowledge
    std::optional<KnowledgeEntry> query(const std::string& category, const std::string& key) {
        std::unique_lock lock(mutex_);
        std::string full_key = category + "::" + key;
        auto it = entries_.find(full_key);
        if (it != entries_.end()) {
            it->second.last_accessed = std::chrono::steady_clock::now();
            it->second.access_count++;
            return it->second;
        }
        return std::nullopt;
    }

    // Search across all categories
    std::vector<KnowledgeEntry> search(const std::string& query_str) {
        std::shared_lock lock(mutex_);
        std::vector<KnowledgeEntry> results;
        std::string lower_query = query_str;
        std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);
        
        for (const auto& [key, entry] : entries_) {
            std::string lower_key = entry.key;
            std::string lower_value = entry.value;
            std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
            std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);
            
            if (lower_key.find(lower_query) != std::string::npos ||
                lower_value.find(lower_query) != std::string::npos) {
                results.push_back(entry);
            }
        }
        
        // Sort by access count (most popular first)
        std::sort(results.begin(), results.end(), 
            [](const KnowledgeEntry& a, const KnowledgeEntry& b) {
                return a.access_count > b.access_count;
            });
        
        return results;
    }

    // Get entries by category
    std::vector<KnowledgeEntry> getByCategory(const std::string& category) {
        std::shared_lock lock(mutex_);
        std::vector<KnowledgeEntry> results;
        for (const auto& [key, entry] : entries_) {
            if (entry.category == category) {
                results.push_back(entry);
            }
        }
        return results;
    }

    // Mark an entry as verified
    void verifyEntry(const std::string& category, const std::string& key) {
        std::unique_lock lock(mutex_);
        std::string full_key = category + "::" + key;
        auto it = entries_.find(full_key);
        if (it != entries_.end()) {
            it->second.verified = true;
            it->second.confidence = std::min(1.0, it->second.confidence + 0.1);
        }
    }

    // Update confidence of an entry
    void updateConfidence(const std::string& category, const std::string& key, double delta) {
        std::unique_lock lock(mutex_);
        std::string full_key = category + "::" + key;
        auto it = entries_.find(full_key);
        if (it != entries_.end()) {
            it->second.confidence = std::max(0.0, std::min(1.0, it->second.confidence + delta));
        }
    }

    // Store a successful workflow for reuse
    void storeWorkflow(const std::string& binary_type, const std::vector<std::string>& workflow_steps) {
        std::ostringstream oss;
        for (size_t i = 0; i < workflow_steps.size(); ++i) {
            if (i > 0) oss << " -> ";
            oss << workflow_steps[i];
        }
        addFact("agent_workflows", binary_type, oss.str(), 0.9);
    }

    // Get similar binaries (by type)
    std::vector<KnowledgeEntry> getSimilarBinaries(const std::string& binary_type) {
        return getByCategory("solved_binaries");
    }

    // Export knowledge graph to file
    bool exportToFile(const std::string& path) {
        std::shared_lock lock(mutex_);
        std::ofstream file(path);
        if (!file.is_open()) return false;
        
        file << "KnowledgeGraph Export\n";
        file << "====================\n";
        file << "Total entries: " << total_entries_ << "\n\n";
        
        for (const auto& [cat_name, cat] : categories_) {
            if (cat.entry_count == 0) continue;
            file << "[" << cat_name << "] " << cat.description << " (" << cat.entry_count << " entries)\n";
            
            for (const auto& [key, entry] : entries_) {
                if (entry.category == cat_name) {
                    file << "  " << entry.key << ": " << entry.value 
                         << " (conf: " << entry.confidence 
                         << ", verified: " << (entry.verified ? "yes" : "no")
                         << ", accesses: " << entry.access_count << ")\n";
                }
            }
            file << "\n";
        }
        
        file.close();
        return true;
    }

    // Import knowledge graph from file
    bool importFromFile(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) return false;
        
        std::string line;
        while (std::getline(file, line)) {
            // Simple import - would be more robust in production
            if (line.find("::") != std::string::npos) {
                size_t pos = line.find("::");
                std::string category = line.substr(0, pos);
                std::string rest = line.substr(pos + 2);
                pos = rest.find(": ");
                if (pos != std::string::npos) {
                    std::string key = rest.substr(0, pos);
                    std::string value = rest.substr(pos + 2);
                    addFact(category, key, value);
                }
            }
        }
        
        file.close();
        return true;
    }

    // Get statistics
    struct KGStats {
        size_t total_entries = 0;
        size_t verified_entries = 0;
        size_t categories_count = 0;
        double average_confidence = 0.0;
    };
    
    KGStats getStats() const {
        std::shared_lock lock(mutex_);
        KGStats stats;
        stats.total_entries = total_entries_;
        stats.categories_count = categories_.size();
        
        double total_conf = 0.0;
        for (const auto& [_, entry] : entries_) {
            if (entry.verified) stats.verified_entries++;
            total_conf += entry.confidence;
        }
        stats.average_confidence = total_entries_ > 0 ? total_conf / total_entries_ : 0.0;
        
        return stats;
    }

    // Clear all entries
    void clear() {
        std::unique_lock lock(mutex_);
        entries_.clear();
        total_entries_ = 0;
        for (auto& [_, cat] : categories_) {
            cat.entry_count = 0;
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, KnowledgeEntry> entries_;
    std::unordered_map<std::string, KnowledgeCategory> categories_;
    std::atomic<size_t> total_entries_{0};
};

} // namespace RawrXD::Agentic
