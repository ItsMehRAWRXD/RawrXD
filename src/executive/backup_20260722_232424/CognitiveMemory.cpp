// ============================================================================
// CognitiveMemory.cpp - Implementation
// ============================================================================

#include "CognitiveMemory.hpp"
#include <algorithm>

namespace RawrXD {
namespace Executive {

struct CognitiveMemory::Impl {
    std::unordered_map<std::string, Episode> episodes;
    std::unordered_map<std::string, SemanticNode> semanticNodes;
    std::unordered_map<std::string, ProceduralMemory> workflows;
    mutable std::mutex mutex;
    size_t maxEpisodicSize = 10000;
    size_t maxSemanticSize = 100000;
    size_t totalQueries = 0;
    double totalQueryTimeMs = 0.0;
};

CognitiveMemory::CognitiveMemory() : pImpl_(std::make_unique<Impl>()) {}
CognitiveMemory::~CognitiveMemory() = default;

bool CognitiveMemory::Initialize(size_t maxEpisodicSize, size_t maxSemanticSize) {
    pImpl_->maxEpisodicSize = maxEpisodicSize;
    pImpl_->maxSemanticSize = maxSemanticSize;
    return true;
}

void CognitiveMemory::Shutdown() {}

std::string CognitiveMemory::StoreEpisode(const Episode& episode) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->episodes[episode.episodeId] = episode;
    return episode.episodeId;
}

std::optional<Episode> CognitiveMemory::RetrieveEpisode(const std::string& episodeId) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto it = pImpl_->episodes.find(episodeId);
    if (it != pImpl_->episodes.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Episode> CognitiveMemory::QueryEpisodes(const MemoryQuery& query) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    std::vector<Episode> results;
    for (const auto& [id, episode] : pImpl_->episodes) {
        if (!query.domain.empty() && episode.domain != query.domain) continue;
        results.push_back(episode);
    }
    return results;
}

std::string CognitiveMemory::StoreSemanticNode(const SemanticNode& node) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->semanticNodes[node.nodeId] = node;
    return node.nodeId;
}

std::optional<SemanticNode> CognitiveMemory::RetrieveSemanticNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto it = pImpl_->semanticNodes.find(nodeId);
    if (it != pImpl_->semanticNodes.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string CognitiveMemory::StoreWorkflow(const ProceduralMemory& workflow) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->workflows[workflow.workflowId] = workflow;
    return workflow.workflowId;
}

void CognitiveMemory::ConsolidateEpisodicMemory() {}
void CognitiveMemory::ConsolidateSemanticMemory() {}
bool CognitiveMemory::SaveToDisk(const std::string& path) { return true; }
bool CognitiveMemory::LoadFromDisk(const std::string& path) { return true; }

CognitiveMemory::Stats CognitiveMemory::GetStats() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    Stats s;
    s.episodicCount = pImpl_->episodes.size();
    s.semanticCount = pImpl_->semanticNodes.size();
    s.proceduralCount = pImpl_->workflows.size();
    s.totalQueries = pImpl_->totalQueries;
    s.averageQueryTimeMs = pImpl_->totalQueries > 0 ? 
        pImpl_->totalQueryTimeMs / pImpl_->totalQueries : 0.0;
    return s;
}

} // namespace Executive
} // namespace RawrXD
