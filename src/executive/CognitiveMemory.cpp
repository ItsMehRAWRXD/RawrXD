// ============================================================
// CognitiveMemory.cpp - Implementation of Episodic + Semantic + Working memory
// ============================================================

#include "CognitiveMemory.hpp"

namespace RawrXD::Executive {

bool CognitiveMemory::initialize() {
    printf("[Memory] Cognitive Memory initializing...\n");
    
    // Load any persisted memories (from disk/database)
    loadFromDisk();
    
    printf("[Memory]   Episodic: %zu entries\n", episodic_.size());
    printf("[Memory]   Semantic: %zu entries\n", semantic_.size());
    printf("[Memory]   Working: %zu entries\n", working_.size());
    printf("[Memory] ✓ Initialized\n\n");
    
    return true;
}

uint64_t CognitiveMemory::storeEpisode(const EpisodicEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto stored = entry;
    stored.id = nextEpisodicId_++;
    stored.timestampMs = entry.timestampMs > 0 ? entry.timestampMs : currentTimeMs();
    
    episodic_.push_back(stored);
    
    // Trim if too large (keep last 10000)
    if (episodic_.size() > 10000) {
        episodic_.erase(episodic_.begin());
    }
    
    return stored.id;
}

std::vector<EpisodicEntry> CognitiveMemory::getEpisodes(
    const std::string& typeFilter,
    uint64_t sinceMs,
    size_t maxCount) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<EpisodicEntry> result;
    
    // Search backwards (most recent first)
    for (auto it = episodic_.rbegin(); it != episodic_.rend() && 
         result.size() < maxCount; ++it) {
        
        if (sinceMs > 0 && it->timestampMs < sinceMs) continue;
        if (!typeFilter.empty() && it->type != typeFilter) continue;
        
        result.push_back(*it);
    }
    
    return result;
}

uint64_t CognitiveMemory::storeSemantic(const SemanticEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto stored = entry;
    stored.id = nextSemanticId_++;
    stored.timestampMs = entry.timestampMs > 0 ? entry.timestampMs : currentTimeMs();
    stored.lastAccessedMs = stored.timestampMs;
    stored.accessCount = 0;
    
    // Check for existing entry with same category+key
    std::string compositeKey = entry.category + ":" + entry.key;
    auto it = semanticIndex_.find(compositeKey);
    if (it != semanticIndex_.end()) {
        // Update existing
        semantic_[it->second] = stored;
        printf("[Memory] Updated semantic: [%s] %s\n",
               entry.category.c_str(), entry.key.c_str());
    } else {
        // New entry
        semanticIndex_[compositeKey] = stored.id;
        semantic_[stored.id] = stored;
        printf("[Memory] New semantic: [%s] %s (conf %.0f%%)\n",
               entry.category.c_str(), entry.key.c_str(),
               entry.confidence * 100);
    }
    
    return stored.id;
}

std::optional<SemanticEntry> CognitiveMemory::querySemantic(
    const std::string& category, const std::string& key) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string compositeKey = category + ":" + key;
    auto it = semanticIndex_.find(compositeKey);
    if (it == semanticIndex_.end()) return std::nullopt;
    
    auto& entry = semantic_[it->second];
    entry.accessCount++;
    entry.lastAccessedMs = currentTimeMs();
    
    return entry;
}

std::vector<SemanticEntry> CognitiveMemory::queryByCategory(const std::string& category) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<SemanticEntry> result;
    for (const auto& [id, entry] : semantic_) {
        if (entry.category == category && !entry.deprecated) {
            result.push_back(entry);
        }
    }
    return result;
}

std::vector<SemanticEntry> CognitiveMemory::queryByAddress(const std::string& address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<SemanticEntry> result;
    for (const auto& [id, entry] : semantic_) {
        for (const auto& ref : entry.references) {
            if (ref == address) {
                result.push_back(entry);
                break;
            }
        }
    }
    return result;
}

bool CognitiveMemory::markVerified(uint64_t semanticId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = semantic_.find(semanticId);
    if (it == semantic_.end()) return false;
    
    it->second.verified = true;
    it->second.confidence = std::max(it->second.confidence, 0.85f);
    return true;
}

bool CognitiveMemory::deprecate(uint64_t semanticId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = semantic_.find(semanticId);
    if (it == semantic_.end()) return false;
    
    it->second.deprecated = true;
    return true;
}

void CognitiveMemory::setWorking(const std::string& key, const std::string& value, 
                float priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    working_[key] = {
        .key = key,
        .value = value,
        .timestampMs = currentTimeMs(),
        .priority = priority
    };
}

std::optional<std::string> CognitiveMemory::getWorking(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = working_.find(key);
    if (it == working_.end()) return std::nullopt;
    return it->second.value;
}

void CognitiveMemory::clearWorking() {
    std::lock_guard<std::mutex> lock(mutex_);
    working_.clear();
}

CognitiveMemory::RecallResult CognitiveMemory::recall(const std::string& query) {
    RecallResult result;
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Search episodic
    for (const auto& e : episodic_) {
        if (e.description.find(query) != std::string::npos ||
            e.type.find(query) != std::string::npos) {
            result.episodes.push_back(e);
        }
    }
    
    // Search semantic
    for (const auto& [id, s] : semantic_) {
        if (s.key.find(query) != std::string::npos ||
            s.value.find(query) != std::string::npos ||
            s.category.find(query) != std::string::npos) {
            if (!s.deprecated) {
                result.semantics.push_back(s);
            }
        }
    }
    
    // Search working
    for (const auto& [k, w] : working_) {
        if (k.find(query) != std::string::npos ||
            w.value.find(query) != std::string::npos) {
            result.working.push_back(w);
        }
    }
    
    return result;
}

void CognitiveMemory::consolidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    printf("[Memory] Consolidating working memory → semantic...\n");
    
    size_t promoted = 0;
    for (const auto& [key, w] : working_) {
        // If working entry has high priority and is old enough,
        // promote to semantic
        if (w.priority > 0.7f) {
            storeSemantic({
                .category = "working_promoted",
                .key = key,
                .value = w.value,
                .source = "consolidation",
                .confidence = w.priority,
                .timestampMs = w.timestampMs,
                .references = {},
                .verified = false,
                .deprecated = false
            });
            promoted++;
        }
    }
    
    printf("[Memory]   Promoted %zu working entries to semantic\n", promoted);
    
    // Forget old low-confidence semantic entries
    size_t forgotten = 0;
    uint64_t now = currentTimeMs();
    for (auto& [id, s] : semantic_) {
        // If entry is > 1 hour old and confidence < 0.3 → forget
        if (s.confidence < 0.3f && 
            (now - s.timestampMs) > 3600000) {
            s.deprecated = true;
            forgotten++;
        }
    }
    
    printf("[Memory]   Forgot %zu low-confidence entries\n", forgotten);
}

size_t CognitiveMemory::getEpisodicCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    return episodic_.size();
}

size_t CognitiveMemory::getSemanticCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, s] : semantic_) {
        if (!s.deprecated) count++;
    }
    return count;
}

size_t CognitiveMemory::getWorkingCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    return working_.size();
}

void CognitiveMemory::loadFromDisk() {
    // In real implementation: load from disk/database
    // For now: start empty
}

uint64_t CognitiveMemory::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

} // namespace RawrXD::Executive
