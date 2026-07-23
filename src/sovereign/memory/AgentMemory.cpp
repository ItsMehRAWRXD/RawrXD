// ============================================================================
// AgentMemory.cpp - Long-term Memory System Implementation
// ============================================================================

#include "AgentMemory.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <cmath>
#include <filesystem>
#include <direct.h>

namespace fs = std::filesystem;

namespace Sovereign {

// Simple embedding calculation (production would use real embeddings)
std::vector<float> CalculateEmbedding(const std::string& text) {
    std::vector<float> embedding(128, 0.0f);
    std::hash<std::string> hasher;
    
    // Simple feature extraction
    for (size_t i = 0; i < text.size(); i += 4) {
        std::string chunk = text.substr(i, 4);
        size_t hash = hasher(chunk);
        embedding[hash % 128] += 1.0f;
    }
    
    // Normalize
    float norm = 0.0f;
    for (float v : embedding) norm += v * v;
    norm = std::sqrt(norm);
    if (norm > 0) {
        for (auto& v : embedding) v /= norm;
    }
    
    return embedding;
}

float CosineSimilarity(const std::vector<float>& a, const std::vector<float>& b) {
    float dot = 0.0f;
    for (size_t i = 0; i < a.size() && i < b.size(); ++i) {
        dot += a[i] * b[i];
    }
    return dot;
}

class AgentMemory::Impl {
public:
    std::unordered_map<uint64_t, Memory> memories_;
    std::unordered_map<uint64_t, Conversation> conversations_;
    std::unordered_map<std::string, std::string> workingMemory_;
    std::unordered_map<std::string, std::vector<uint64_t>> tagIndex_;
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, std::string>>> memoryLinks_;
    
    uint64_t nextMemoryId_ = 1;
    uint64_t nextConversationId_ = 1;
    std::string dbPath_;
    mutable std::mutex mutex_;
    
    Impl(const std::string& path) : dbPath_(path) {
        _mkdir(path.c_str());
        Load();
    }
    
    ~Impl() {
        Save();
    }
    
    uint64_t Store(const Memory& memory) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        Memory mem = memory;
        mem.id = nextMemoryId_++;
        mem.timestamp = GetTimestamp();
        mem.lastAccessed = mem.timestamp;
        mem.accessCount = 0;
        
        if (mem.embedding.empty()) {
            mem.embedding = CalculateEmbedding(mem.content);
        }
        
        memories_[mem.id] = mem;
        
        // Index by tags
        for (const auto& tag : mem.tags) {
            tagIndex_[tag].push_back(mem.id);
        }
        
        return mem.id;
    }
    
    std::vector<MemoryResult> Retrieve(const MemoryQuery& query) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MemoryResult> results;
        
        auto queryEmbedding = CalculateEmbedding(query.content);
        
        for (auto& [id, mem] : memories_) {
            // Filter by type
            if (query.typeFilter != MemoryType::EPISODIC && 
                mem.type != query.typeFilter) continue;
            
            // Filter by importance
            if (mem.importance < query.minImportance) continue;
            
            // Filter by time
            if (query.since > 0 && mem.timestamp < query.since) continue;
            if (query.until > 0 && mem.timestamp > query.until) continue;
            
            // Filter by tags
            if (!query.tags.empty()) {
                bool hasTag = false;
                for (const auto& tag : query.tags) {
                    if (std::find(mem.tags.begin(), mem.tags.end(), tag) != mem.tags.end()) {
                        hasTag = true;
                        break;
                    }
                }
                if (!hasTag) continue;
            }
            
            // Calculate relevance
            MemoryResult result;
            result.memory = mem;
            result.relevance = CosineSimilarity(queryEmbedding, mem.embedding);
            result.recency = CalculateRecency(mem.lastAccessed);
            result.importance = mem.importance;
            results.push_back(result);
        }
        
        // Sort by combined score
        std::sort(results.begin(), results.end(), 
            [](const MemoryResult& a, const MemoryResult& b) {
                float scoreA = a.relevance * 0.5f + a.recency * 0.3f + a.importance * 0.2f;
                float scoreB = b.relevance * 0.5f + b.recency * 0.3f + b.importance * 0.2f;
                return scoreA > scoreB;
            });
        
        if (results.size() > query.limit) {
            results.resize(query.limit);
        }
        
        return results;
    }
    
    std::vector<MemoryResult> RetrieveSimilar(const std::string& content, size_t topK) {
        MemoryQuery query;
        query.content = content;
        query.limit = topK;
        return Retrieve(query);
    }
    
    void SetWorkingMemory(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        workingMemory_[key] = value;
    }
    
    std::optional<std::string> GetWorkingMemory(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = workingMemory_.find(key);
        if (it != workingMemory_.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    
    uint64_t CreateConversation(const std::string& title) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        Conversation conv;
        conv.id = nextConversationId_++;
        conv.title = title;
        conv.created = GetTimestamp();
        conv.updated = conv.created;
        
        conversations_[conv.id] = conv;
        return conv.id;
    }
    
    void AddTurn(uint64_t conversationId, const ConversationTurn& turn) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = conversations_.find(conversationId);
        if (it == conversations_.end()) return;
        
        ConversationTurn t = turn;
        t.id = it->second.turns.size();
        t.timestamp = GetTimestamp();
        
        it->second.turns.push_back(t);
        it->second.updated = t.timestamp;
    }
    
    void Consolidate() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Find similar memories and merge
        std::vector<uint64_t> toRemove;
        
        for (auto& [id1, mem1] : memories_) {
            for (auto& [id2, mem2] : memories_) {
                if (id1 >= id2) continue;
                if (mem1.type != mem2.type) continue;
                
                float similarity = CosineSimilarity(mem1.embedding, mem2.embedding);
                if (similarity > 0.9f) {
                    // Merge mem2 into mem1
                    mem1.content += " | " + mem2.content;
                    mem1.importance = std::max(mem1.importance, mem2.importance);
                    toRemove.push_back(id2);
                }
            }
        }
        
        for (uint64_t id : toRemove) {
            memories_.erase(id);
        }
    }
    
    void Prune(float threshold) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<uint64_t> toRemove;
        for (auto& [id, mem] : memories_) {
            if (mem.importance < threshold && mem.accessCount < 3) {
                toRemove.push_back(id);
            }
        }
        
        for (uint64_t id : toRemove) {
            memories_.erase(id);
        }
    }
    
    void Save() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::ofstream file(dbPath_ + "/memories.db", std::ios::binary);
        if (!file) return;
        
        // Write memory count
        uint64_t count = memories_.size();
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));
        
        // Write each memory
        for (const auto& [id, mem] : memories_) {
            file.write(reinterpret_cast<const char*>(&mem.id), sizeof(mem.id));
            file.write(reinterpret_cast<const char*>(&mem.type), sizeof(mem.type));
            
            uint32_t contentLen = mem.content.size();
            file.write(reinterpret_cast<const char*>(&contentLen), sizeof(contentLen));
            file.write(mem.content.data(), contentLen);
            
            file.write(reinterpret_cast<const char*>(&mem.timestamp), sizeof(mem.timestamp));
            file.write(reinterpret_cast<const char*>(&mem.importance), sizeof(mem.importance));
        }
    }
    
    void Load() {
        std::ifstream file(dbPath_ + "/memories.db", std::ios::binary);
        if (!file) return;
        
        uint64_t count;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));
        
        for (uint64_t i = 0; i < count; ++i) {
            Memory mem;
            
            file.read(reinterpret_cast<char*>(&mem.id), sizeof(mem.id));
            file.read(reinterpret_cast<char*>(&mem.type), sizeof(mem.type));
            
            uint32_t contentLen;
            file.read(reinterpret_cast<char*>(&contentLen), sizeof(contentLen));
            mem.content.resize(contentLen);
            file.read(mem.content.data(), contentLen);
            
            file.read(reinterpret_cast<char*>(&mem.timestamp), sizeof(mem.timestamp));
            file.read(reinterpret_cast<char*>(&mem.importance), sizeof(mem.importance));
            
            mem.embedding = CalculateEmbedding(mem.content);
            memories_[mem.id] = mem;
            nextMemoryId_ = std::max(nextMemoryId_, mem.id + 1);
        }
    }
    
    uint64_t GetTimestamp() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    float CalculateRecency(uint64_t lastAccessed) {
        uint64_t now = GetTimestamp();
        uint64_t age = now - lastAccessed;
        // Exponential decay
        return std::exp(-age / 86400000.0f); // 1 day half-life
    }
};

// AgentMemory public methods
AgentMemory::AgentMemory(const std::string& dbPath) : pImpl(std::make_unique<Impl>(dbPath)) {}
AgentMemory::~AgentMemory() = default;

uint64_t AgentMemory::Store(const Memory& memory) {
    return pImpl->Store(memory);
}

uint64_t AgentMemory::StoreEpisodic(const std::string& event, const std::string& source) {
    Memory mem;
    mem.type = MemoryType::EPISODIC;
    mem.content = event;
    mem.source = source;
    mem.importance = 0.7f;
    return Store(mem);
}

uint64_t AgentMemory::StoreSemantic(const std::string& fact, const std::vector<std::string>& tags) {
    Memory mem;
    mem.type = MemoryType::SEMANTIC;
    mem.content = fact;
    mem.tags = tags;
    mem.importance = 0.8f;
    return Store(mem);
}

uint64_t AgentMemory::StoreProcedural(const std::string& skill, const std::string& howTo) {
    Memory mem;
    mem.type = MemoryType::PROCEDURAL;
    mem.content = skill + ": " + howTo;
    mem.importance = 0.9f;
    return Store(mem);
}

uint64_t AgentMemory::StoreWorking(const std::string& context) {
    Memory mem;
    mem.type = MemoryType::WORKING;
    mem.content = context;
    mem.importance = 0.5f;
    return Store(mem);
}

uint64_t AgentMemory::StoreReflection(const std::string& insight, float importance) {
    Memory mem;
    mem.type = MemoryType::REFLECTION;
    mem.content = insight;
    mem.importance = importance;
    return Store(mem);
}

std::vector<MemoryResult> AgentMemory::Retrieve(const MemoryQuery& query) {
    return pImpl->Retrieve(query);
}

std::vector<MemoryResult> AgentMemory::RetrieveSimilar(const std::string& content, size_t topK) {
    return pImpl->RetrieveSimilar(content, topK);
}

void AgentMemory::SetWorkingMemory(const std::string& key, const std::string& value) {
    pImpl->SetWorkingMemory(key, value);
}

std::optional<std::string> AgentMemory::GetWorkingMemory(const std::string& key) {
    return pImpl->GetWorkingMemory(key);
}

uint64_t AgentMemory::CreateConversation(const std::string& title) {
    return pImpl->CreateConversation(title);
}

void AgentMemory::AddTurn(uint64_t conversationId, const ConversationTurn& turn) {
    pImpl->AddTurn(conversationId, turn);
}

void AgentMemory::Consolidate() {
    pImpl->Consolidate();
}

void AgentMemory::Prune(float threshold) {
    pImpl->Prune(threshold);
}

void AgentMemory::Save() {
    pImpl->Save();
}

void AgentMemory::Load() {
    pImpl->Load();
}

size_t AgentMemory::GetMemoryCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->memories_.size();
}

// MemoryAugmentedPrompt implementation
std::string MemoryAugmentedPrompt::Build(
    AgentMemory& memory,
    const std::string& currentTask,
    const std::string& recentContext,
    size_t maxTokens
) {
    std::string prompt;
    
    // System instruction
    prompt += "You are Sovereign Agent, an autonomous coding assistant.\n\n";
    
    // Retrieve relevant memories
    MemoryQuery query;
    query.content = currentTask;
    query.limit = 10;
    query.minImportance = 0.5f;
    
    auto memories = memory.Retrieve(query);
    
    if (!memories.empty()) {
        prompt += "Relevant context from memory:\n";
        for (const auto& result : memories) {
            prompt += "- " + result.memory.content + "\n";
        }
        prompt += "\n";
    }
    
    // Recent conversation context
    if (!recentContext.empty()) {
        prompt += "Recent conversation:\n" + recentContext + "\n\n";
    }
    
    // Current task
    prompt += "Task: " + currentTask + "\n";
    prompt += "Respond with the appropriate tool calls or analysis.\n";
    
    return prompt;
}

} // namespace Sovereign
