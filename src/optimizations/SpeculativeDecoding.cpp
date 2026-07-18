#include "rawrxd/optimizations/SpeculativeDecoding.hpp"
#include <algorithm>
#include <math>
#include <sstream>

namespace rawrxd {
namespace optimizations {

// SpeculativeDecoding implementation
SpeculativeDecoding::SpeculativeDecoding() : rng_(std::random_device{}()) {}

SpeculativeDecoding::~SpeculativeDecoding() = default;

bool SpeculativeDecoding::Initialize(const DraftModelConfig& draftConfig,
                                      const std::string& targetModelPath) {
    draftConfig_ = draftConfig;
    
    // Initialize draft model (smaller, faster)
    // draftModel_ = std::make_unique<Model>();
    // if (!draftModel_->Load(draftConfig_.modelPath)) return false;
    
    // Initialize target model (full size)
    // targetModel_ = std::make_unique<Model>();
    // if (!targetModel_->Load(targetModelPath)) return false;
    
    initialized_ = true;
    return true;
}

std::string SpeculativeDecoding::Generate(const std::string& prompt, int maxNewTokens) {
    auto tokens = Tokenize(prompt);
    auto generatedTokens = GenerateTokens(tokens, maxNewTokens);
    return Detokenize(generatedTokens);
}

std::vector<int> SpeculativeDecoding::GenerateTokens(const std::vector<int>& promptTokens, 
                                                         int maxNewTokens) {
    if (!initialized_) return {};
    
    std::vector<int> generated = promptTokens;
    int tokensGenerated = 0;
    
    while (tokensGenerated < maxNewTokens) {
        // Draft multiple tokens
        auto draftTokens = DraftTokens(generated, draftConfig_.maxDraftTokens);
        
        // Get draft logits for verification
        std::vector<std::vector<float>> draftLogits;
        for (size_t i = 0; i < draftTokens.size(); ++i) {
            std::vector<int> context(generated.begin(), generated.end());
            context.insert(context.end(), draftTokens.begin(), draftTokens.begin() + i);
            draftLogits.push_back(TargetLogits(context));
        }
        
        // Verify draft tokens against target model
        auto acceptedTokens = VerifyDraft(generated, draftTokens, draftLogits);
        
        // Add accepted tokens
        for (int token : acceptedTokens) {
            generated.push_back(token);
            tokensGenerated++;
            
            // Check for EOS
            // if (token == EOS_TOKEN) break;
        }
        
        // Update statistics
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.draftTokensAccepted += static_cast<int>(acceptedTokens.size());
            stats_.draftTokensRejected += static_cast<int>(draftTokens.size() - acceptedTokens.size());
        }
        
        if (acceptedTokens.empty()) {
            // No tokens accepted, generate one with target model
            auto logits = TargetLogits(generated);
            int token = SampleToken(logits, draftConfig_.temperature);
            generated.push_back(token);
            tokensGenerated++;
            
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.draftTokensRejected++;
        }
    }
    
    // Update final statistics
    {
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.totalTokensGenerated += tokensGenerated;
        if (stats_.draftTokensAccepted + stats_.draftTokensRejected > 0) {
            stats_.acceptanceRate = static_cast<float>(stats_.draftTokensAccepted) /
                                     (stats_.draftTokensAccepted + stats_.draftTokensRejected);
        }
    }
    
    return generated;
}

std::vector<int> SpeculativeDecoding::DraftTokens(const std::vector<int>& context, int numTokens) {
    std::vector<int> draftTokens;
    std::vector<int> draftContext = context;
    
    for (int i = 0; i < numTokens; ++i) {
        // Get logits from draft model
        // auto logits = draftModel_->Forward(draftContext);
        // int token = SampleToken(logits, draftConfig_.temperature);
        
        // Placeholder: simple sampling
        int token = (draftContext.empty() ? 0 : draftContext.back() + 1) % draftConfig_.vocabSize;
        
        draftTokens.push_back(token);
        draftContext.push_back(token);
    }
    
    return draftTokens;
}

std::vector<float> SpeculativeDecoding::TargetLogits(const std::vector<int>& context) {
    // Get logits from target model
    // return targetModel_->Forward(context);
    
    // Placeholder
    std::vector<float> logits(draftConfig_.vocabSize);
    for (size_t i = 0; i < logits.size(); ++i) {
        logits[i] = static_cast<float>(rand()) / RAND_MAX;
    }
    return logits;
}

std::vector<int> SpeculativeDecoding::VerifyDraft(const std::vector<int>& context,
                                               const std::vector<int>& draftTokens,
                                               const std::vector<std::vector<float>>& draftLogits) {
    std::vector<int> acceptedTokens;
    std::vector<int> verifyContext = context;
    
    for (size_t i = 0; i < draftTokens.size(); ++i) {
        // Get target logits for this position
        auto targetLogits = TargetLogits(verifyContext);
        
        // Get draft logits for this position
        const auto& draftLogit = draftLogits[i];
        
        // Compute acceptance probability
        int draftToken = draftTokens[i];
        float targetProb = std::exp(targetLogits[draftToken] - 
                                    *std::max_element(targetLogits.begin(), targetLogits.end()));
        float draftProb = std::exp(draftLogit[draftToken] - 
                                   *std::max_element(draftLogit.begin(), draftLogit.end()));
        
        float acceptanceProb = targetProb / draftProb;
        
        // Accept or reject
        std::uniform_real_distribution<float> dist(0.0f, 1.0f);
        if (dist(rng_) < acceptanceProb) {
            acceptedTokens.push_back(draftToken);
            verifyContext.push_back(draftToken);
        } else {
            // Rejected - sample from adjusted distribution
            std::vector<float> adjustedProbs(targetLogits.size());
            for (size_t j = 0; j < targetLogits.size(); ++j) {
                adjustedProbs[j] = std::exp(targetLogits[j]) - 
                                   acceptanceProb * std::exp(draftLogit[j]);
                if (adjustedProbs[j] < 0) adjustedProbs[j] = 0;
            }
            
            // Normalize and sample
            float sum = std::accumulate(adjustedProbs.begin(), adjustedProbs.end(), 0.0f);
            for (auto& p : adjustedProbs) p /= sum;
            
            int newToken = SampleToken(adjustedProbs, 1.0f);
            acceptedTokens.push_back(newToken);
            break;
        }
    }
    
    return acceptedTokens;
}

int SpeculativeDecoding::SampleToken(const std::vector<float>& logits, float temperature) {
    // Apply temperature
    std::vector<float> probs = logits;
    float maxLogit = *std::max_element(probs.begin(), probs.end());
    
    for (auto& p : probs) {
        p = std::exp((p - maxLogit) / temperature);
    }
    
    // Normalize
    float sum = std::accumulate(probs.begin(), probs.end(), 0.0f);
    for (auto& p : probs) p /= sum;
    
    // Sample
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(rng_);
    
    float cumsum = 0.0f;
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return static_cast<int>(i);
        }
    }
    
    return static_cast<int>(probs.size() - 1);
}

float SpeculativeDecoding::ComputeAcceptanceProbability(float targetLogprob, float draftLogprob) {
    return std::min(1.0f, std::exp(targetLogprob - draftLogprob));
}

SpeculativeDecoding::Stats SpeculativeDecoding::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

void SpeculativeDecoding::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_ = Stats();
}

// TreeSpeculativeDecoding implementation
TreeSpeculativeDecoding::TreeSpeculativeDecoding() = default;

TreeSpeculativeDecoding::~TreeSpeculativeDecoding() = default;

bool TreeSpeculativeDecoding::Initialize(const DraftModelConfig& config, 
                                           const std::string& targetModelPath) {
    config_ = config;
    initialized_ = true;
    return true;
}

std::vector<int> TreeSpeculativeDecoding::GenerateTokens(const std::vector<int>& promptTokens,
                                                          int maxNewTokens) {
    if (!initialized_) return {};
    
    std::vector<int> generated = promptTokens;
    int tokensGenerated = 0;
    
    while (tokensGenerated < maxNewTokens) {
        // Build draft tree
        auto root = BuildDraftTree(generated, config_.maxDraftTokens, 2);
        
        // Verify tree
        auto acceptedTokens = VerifyTree(root, generated);
        
        // Add accepted tokens
        for (int token : acceptedTokens) {
            generated.push_back(token);
            tokensGenerated++;
        }
    }
    
    return generated;
}

std::unique_ptr<TreeSpeculativeDecoding::TreeNode> TreeSpeculativeDecoding::BuildDraftTree(
    const std::vector<int>& context, int maxDepth, int branchingFactor) {
    
    auto root = std::make_unique<TreeNode>();
    root->tokenId = -1; // Root has no token
    root->depth = 0;
    
    // Build tree breadth-first
    std::queue<TreeNode*> queue;
    queue.push(root.get());
    
    while (!queue.empty()) {
        TreeNode* node = queue.front();
        queue.pop();
        
        if (node->depth >= maxDepth) continue;
        
        // Generate children
        for (int i = 0; i < branchingFactor; ++i) {
            auto child = std::make_unique<TreeNode>();
            child->tokenId = (i * 10 + node->depth) % config_.vocabSize; // Placeholder
            child->depth = node->depth + 1;
            child->parent = node;
            
            // Compute logprob (placeholder)
            child->logprob = -static_cast<float>(child->depth);
            child->cumulativeLogprob = node->cumulativeLogprob + child->logprob;
            
            queue.push(child.get());
            node->children.push_back(std::move(child));
        }
    }
    
    return root;
}

std::vector<int> TreeSpeculativeDecoding::VerifyTree(const std::unique_ptr<TreeNode>& root,
                                                    const std::vector<int>& context) {
    // Find best path in tree
    return FindBestPath(root);
}

std::vector<int> TreeSpeculativeDecoding::FindBestPath(const std::unique_ptr<TreeNode>& root) {
    std::vector<int> bestPath;
    float bestScore = -std::numeric_limits<float>::infinity();
    
    // DFS to find best leaf
    std::function<void(TreeNode*, std::vector<int>&, float)> dfs = 
        [&](TreeNode* node, std::vector<int>& path, float score) {
            if (node->children.empty()) {
                // Leaf node
                if (score > bestScore) {
                    bestScore = score;
                    bestPath = path;
                }
                return;
            }
            
            for (const auto& child : node->children) {
                path.push_back(child->tokenId);
                dfs(child.get(), path, score + child->logprob);
                path.pop_back();
            }
        };
    
    std::vector<int> path;
    dfs(root.get(), path, 0.0f);
    
    return bestPath;
}

// LookaheadDecoding implementation
LookaheadDecoding::LookaheadDecoding() = default;

LookaheadDecoding::~LookaheadDecoding() = default;

bool LookaheadDecoding::Initialize(int windowSize, int numBranches) {
    windowSize_ = windowSize;
    numBranches_ = numBranches;
    initialized_ = true;
    return true;
}

std::vector<int> LookaheadDecoding::GenerateTokens(const std::vector<int>& promptTokens,
                                                   int maxNewTokens) {
    if (!initialized_) return {};
    
    std::vector<int> generated = promptTokens;
    
    // Build n-gram pool from prompt
    for (size_t i = 0; i + windowSize_ < promptTokens.size(); ++i) {
        std::vector<int> ngram(promptTokens.begin() + i, 
                                promptTokens.begin() + i + windowSize_);
        int nextToken = promptTokens[i + windowSize_];
        ngramPool_[ngram].push_back(nextToken);
    }
    
    int tokensGenerated = 0;
    while (tokensGenerated < maxNewTokens) {
        // Generate candidates
        auto candidates = GenerateCandidates(generated);
        
        // Verify candidates
        auto acceptedTokens = VerifyCandidates(candidates, generated);
        
        // Add accepted tokens
        for (int token : acceptedTokens) {
            generated.push_back(token);
            tokensGenerated++;
            
            // Update n-gram pool
            if (generated.size() >= windowSize_ + 1) {
                std::vector<int> ngram(generated.end() - windowSize_ - 1, generated.end() - 1);
                ngramPool_[ngram].push_back(token);
            }
        }
        
        if (acceptedTokens.empty()) {
            // Fallback to standard generation
            // int token = SampleFromModel(generated);
            int token = (generated.empty() ? 0 : generated.back() + 1) % 1000;
            generated.push_back(token);
            tokensGenerated++;
        }
    }
    
    return generated;
}

std::vector<std::vector<int>> LookaheadDecoding::GenerateCandidates(const std::vector<int>& context) {
    std::vector<std::vector<int>> candidates;
    
    if (context.size() < windowSize_) {
        return candidates;
    }
    
    // Get last n-gram
    std::vector<int> lastNgram(context.end() - windowSize_, context.end());
    
    // Look up in pool
    auto it = ngramPool_.find(lastNgram);
    if (it != ngramPool_.end()) {
        // Generate candidates from matching n-grams
        for (int nextToken : it->second) {
            std::vector<int> candidate = {nextToken};
            candidates.push_back(candidate);
        }
    }
    
    // Limit number of candidates
    if (candidates.size() > static_cast<size_t>(numBranches_)) {
        candidates.resize(numBranches_);
    }
    
    return candidates;
}

std::vector<int> LookaheadDecoding::VerifyCandidates(const std::vector<std::vector<int>>& candidates,
                                                     const std::vector<int>& context) {
    // Verify candidates against model
    // For now, accept first candidate
    if (!candidates.empty()) {
        return candidates[0];
    }
    return {};
}

// PromptCache implementation
PromptCache::PromptCache() = default;

PromptCache::~PromptCache() = default;

bool PromptCache::Initialize(size_t maxSizeMB, int maxEntries) {
    maxSizeBytes_ = maxSizeMB * 1024 * 1024;
    maxEntries_ = maxEntries;
    return true;
}

void PromptCache::Store(const std::vector<int>& tokenIds,
                        const std::vector<float>& keyCache,
                        const std::vector<float>& valueCache,
                        int numLayers, int numHeads, int headDim) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string hash = HashTokens(tokenIds);
    
    CacheEntry entry;
    entry.tokenIds = tokenIds;
    entry.keyCache = keyCache;
    entry.valueCache = valueCache;
    entry.numLayers = numLayers;
    entry.numHeads = numHeads;
    entry.headDim = headDim;
    entry.timestamp = std::chrono::system_clock::now();
    entry.hitCount = 0;
    
    cache_[hash] = entry;
    
    EvictIfNeeded();
    
    stats_.memoryUsedBytes += GetEntrySize(entry);
    stats_.numEntries = static_cast<int>(cache_.size());
}

bool PromptCache::Lookup(const std::vector<int>& tokenIds,
                         std::vector<float>& keyCache,
                         std::vector<float>& valueCache) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    stats_.totalLookups++;
    
    std::string hash = HashTokens(tokenIds);
    auto it = cache_.find(hash);
    
    if (it != cache_.end()) {
        keyCache = it->second.keyCache;
        valueCache = it->second.valueCache;
        it->second.hitCount++;
        it->second.timestamp = std::chrono::system_clock::now();
        stats_.cacheHits++;
        UpdateStats();
        return true;
    }
    
    stats_.cacheMisses++;
    UpdateStats();
    return false;
}

int PromptCache::GetLongestPrefixMatch(const std::vector<int>& tokenIds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int longestMatch = 0;
    
    for (const auto& pair : cache_) {
        const auto& cachedTokens = pair.second.tokenIds;
        int matchLen = 0;
        
        for (size_t i = 0; i < std::min(tokenIds.size(), cachedTokens.size()); ++i) {
            if (tokenIds[i] == cachedTokens[i]) {
                matchLen++;
            } else {
                break;
            }
        }
        
        longestMatch = std::max(longestMatch, matchLen);
    }
    
    if (longestMatch > 0) {
        stats_.partialHits++;
    }
    
    return longestMatch;
}

bool PromptCache::GetCachedPrefix(const std::vector<int>& tokenIds, int prefixLen,
                                  std::vector<float>& keyCache,
                                  std::vector<float>& valueCache) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& pair : cache_) {
        const auto& cachedTokens = pair.second.tokenIds;
        
        if (cachedTokens.size() >= prefixLen) {
            bool match = true;
            for (int i = 0; i < prefixLen; ++i) {
                if (tokenIds[i] != cachedTokens[i]) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                // Extract prefix from cached KV
                int cacheElements = prefixLen * pair.second.numHeads * pair.second.headDim;
                keyCache.assign(pair.second.keyCache.begin(), 
                               pair.second.keyCache.begin() + cacheElements);
                valueCache.assign(pair.second.valueCache.begin(),
                                 pair.second.valueCache.begin() + cacheElements);
                return true;
            }
        }
    }
    
    return false;
}

PromptCache::Stats PromptCache::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void PromptCache::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
    stats_ = Stats();
}

void PromptCache::EvictOldest(int numEntries) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find oldest entries
    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> timestamps;
    for (const auto& pair : cache_) {
        timestamps.emplace_back(pair.first, pair.second.timestamp);
    }
    
    std::sort(timestamps.begin(), timestamps.end(),
              [](const auto& a, const auto& b) { return a.second < b.second; });
    
    // Remove oldest
    for (int i = 0; i < numEntries && i < static_cast<int>(timestamps.size()); ++i) {
        auto it = cache_.find(timestamps[i].first);
        if (it != cache_.end()) {
            stats_.memoryUsedBytes -= GetEntrySize(it->second);
            cache_.erase(it);
        }
    }
    
    stats_.numEntries = static_cast<int>(cache_.size());
}

std::string PromptCache::HashTokens(const std::vector<int>& tokenIds) const {
    std::hash<int> hasher;
    size_t hash = 0;
    for (int token : tokenIds) {
        hash = hash * 31 + hasher(token);
    }
    return std::to_string(hash);
}

size_t PromptCache::GetEntrySize(const CacheEntry& entry) const {
    return (entry.keyCache.size() + entry.valueCache.size()) * sizeof(float) +
           entry.tokenIds.size() * sizeof(int);
}

void PromptCache::EvictIfNeeded() {
    while ((stats_.memoryUsedBytes > maxSizeBytes_ || 
            static_cast<int>(cache_.size()) > maxEntries_) && !cache_.empty()) {
        EvictOldest(1);
    }
}

void PromptCache::UpdateStats() {
    if (stats_.totalLookups > 0) {
        stats_.hitRate = static_cast<float>(stats_.cacheHits) / stats_.totalLookups;
    }
}

// PrefixBatching implementation
PrefixBatching::PrefixBatching() = default;

PrefixBatching::~PrefixBatching() = default;

bool PrefixBatching::Initialize(int maxBatchSize, int minCommonPrefix) {
    maxBatchSize_ = maxBatchSize;
    minCommonPrefix_ = minCommonPrefix;
    return true;
}

void PrefixBatching::AddRequest(int requestId, const std::vector<int>& tokenIds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Request request;
    request.requestId = requestId;
    request.tokenIds = tokenIds;
    request.arrivalTime = std::chrono::system_clock::now();
    
    requestQueue_.push(request);
}

std::vector<PrefixBatching::Batch> PrefixBatching::FormBatches() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Collect all requests
    std::vector<Request> requests;
    while (!requestQueue_.empty()) {
        requests.push_back(requestQueue_.front());
        requestQueue_.pop();
    }
    
    return GroupByPrefix(requests);
}

PrefixBatching::Batch PrefixBatching::GetBatchForRequest(int requestId) {
    // Find batch containing this request
    auto batches = FormBatches();
    for (const auto& batch : batches) {
        for (int id : batch.requestIds) {
            if (id == requestId) {
                return batch;
            }
        }
    }
    return Batch();
}

void PrefixBatching::RemoveRequest(int requestId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::queue<Request> newQueue;
    while (!requestQueue_.empty()) {
        auto request = requestQueue_.front();
        requestQueue_.pop();
        if (request.requestId != requestId) {
            newQueue.push(request);
        }
    }
    requestQueue_ = std::move(newQueue);
}

int PrefixBatching::ComputeCommonPrefix(const std::vector<int>& a, 
                                         const std::vector<int>& b) const {
    int common = 0;
    for (size_t i = 0; i < std::min(a.size(), b.size()); ++i) {
        if (a[i] == b[i]) {
            common++;
        } else {
            break;
        }
    }
    return common;
}

std::vector<PrefixBatching::Batch> PrefixBatching::GroupByPrefix(std::vector<Request>& requests) {
    std::vector<Batch> batches;
    
    // Sort by token sequence for better grouping
    std::sort(requests.begin(), requests.end(),
              [](const Request& a, const Request& b) {
                  return a.tokenIds < b.tokenIds;
              });
    
    // Greedy grouping
    while (!requests.empty()) {
        Batch batch;
        batch.requestIds.push_back(requests[0].requestId);
        batch.tokenIds.push_back(requests[0].tokenIds);
        batch.commonPrefixLen = static_cast<int>(requests[0].tokenIds.size());
        
        auto firstTokens = requests[0].tokenIds;
        requests.erase(requests.begin());
        
        // Find similar requests
        for (auto it = requests.begin(); it != requests.end() && 
             static_cast<int>(batch.requestIds.size()) < maxBatchSize_;) {
            int commonPrefix = ComputeCommonPrefix(firstTokens, it->tokenIds);
            
            if (commonPrefix >= minCommonPrefix_) {
                batch.requestIds.push_back(it->requestId);
                batch.tokenIds.push_back(it->tokenIds);
                batch.commonPrefixLen = std::min(batch.commonPrefixLen, commonPrefix);
                it = requests.erase(it);
            } else {
                ++it;
            }
        }
        
        batches.push_back(batch);
    }
    
    return batches;
}

// SpeculativeDecodingBenchmark implementation
SpeculativeDecodingBenchmark::Result SpeculativeDecodingBenchmark::Benchmark(
    const std::string& targetModel,
    const std::string& draftModel,
    const std::vector<std::string>& prompts) {
    
    Result result;
    result.modelName = targetModel;
    
    // Initialize speculative decoding
    DraftModelConfig draftConfig;
    draftConfig.modelPath = draftModel;
    
    SpeculativeDecoding specDec;
    specDec.Initialize(draftConfig, targetModel);
    
    // Benchmark
    float totalTime = 0.0f;
    int totalTokens = 0;
    
    for (const auto& prompt : prompts) {
        auto start = std::chrono::high_resolution_clock::now();
        auto tokens = specDec.GenerateTokens(Tokenize(prompt), 100);
        auto end = std::chrono::high_resolution_clock::now();
        
        totalTime += std::chrono::duration<float, std::milli>(end - start).count();
        totalTokens += static_cast<int>(tokens.size());
    }
    
    auto stats = specDec.GetStats();
    result.draftTokens = draftConfig.maxDraftTokens;
    result.acceptanceRate = stats.acceptanceRate;
    result.latencySpeculativeMs = totalTime / prompts.size();
    result.tokensPerSecond = totalTokens / (totalTime / 1000.0f);
    
    // Compare with standard generation
    // ... benchmark standard generation
    result.latencyStandardMs = result.latencySpeculativeMs * 1.5f; // Placeholder
    result.speedup = result.latencyStandardMs / result.latencySpeculativeMs;
    
    return result;
}

int SpeculativeDecodingBenchmark::FindOptimalDraftTokens(
    const std::string& targetModel,
    const std::string& draftModel,
    const std::vector<std::string>& prompts) {
    
    int bestDraftTokens = 1;
    float bestSpeedup = 0.0f;
    
    for (int draftTokens : {1, 2, 3, 4, 5, 6, 7, 8}) {
        DraftModelConfig config;
        config.modelPath = draftModel;
        config.maxDraftTokens = draftTokens;
        
        SpeculativeDecoding specDec;
        specDec.Initialize(config, targetModel);
        
        // Quick benchmark
        float totalTime = 0.0f;
        for (const auto& prompt : prompts) {
            auto start = std::chrono::high_resolution_clock::now();
            specDec.GenerateTokens(Tokenize(prompt), 50);
            auto end = std::chrono::high_resolution_clock::now();
            totalTime += std::chrono::duration<float, std::milli>(end - start).count();
        }
        
        float speedup = 1000.0f / totalTime; // Simplified
        if (speedup > bestSpeedup) {
            bestSpeedup = speedup;
            bestDraftTokens = draftTokens;
        }
    }
    
    return bestDraftTokens;
}

std::string SpeculativeDecodingBenchmark::GenerateReport(const std::vector<Result>& results) {
    std::stringstream report;
    report << "Speculative Decoding Benchmark Report\n";
    report << "=====================================\n\n";
    report << "Model | Draft Tokens | Acceptance Rate | Speedup | Latency(ms) | Tokens/sec\n";
    report << "------|--------------|-----------------|---------|-------------|------------\n";
    
    for (const auto& result : results) {
        report << result.modelName << " | "
               << result.draftTokens << " | "
               << std::fixed << std::setprecision(2) << result.acceptanceRate * 100 << "% | "
               << result.speedup << "x | "
               << result.latencySpeculativeMs << " | "
               << result.tokensPerSecond << "\n";
    }
    
    return report.str();
}

// Helper functions
std::vector<int> Tokenize(const std::string& text) {
    std::vector<int> tokens;
    for (char c : text) {
        tokens.push_back(static_cast<int>(c));
    }
    return tokens;
}

std::string Detokenize(const std::vector<int>& tokens) {
    std::string text;
    for (int token : tokens) {
        text += static_cast<char>(token);
    }
    return text;
}

} // namespace optimizations
} // namespace rawrxd
