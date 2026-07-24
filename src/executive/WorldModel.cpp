// ============================================================
// WorldModel.cpp - Implementation of Belief-based reasoning-g87
// ============================================================

#include "WorldModel.hpp"

namespace RawrXD::Executive {

bool WorldModel::initialize() {
    printf("[WorldModel] World Model initializing...\n");
    
    // Initialize with default beliefs
    createDefaultBeliefs();
    
    printf("[WorldModel]   Beliefs: %zu\n", beliefs_.size());
    printf("[WorldModel]   Hypotheses: %zu\n", hypotheses_.size());
    printf("[WorldModel] ✓ Initialized\n\n");
    
    return true;
}

uint64_t WorldModel::addBelief(const Belief& belief) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto stored = belief;
    stored.id = nextBeliefId_++;
    stored.timestampMs = currentTimeMs();
    stored.lastUpdatedMs = stored.timestampMs;
    stored.confirmationCount = 0;
    stored.refutationCount = 0;
    
    beliefs_[stored.id] = stored;
    
    printf("[WorldModel] New belief: %s %s (conf %.0f%%)\n",
           belief.subject.c_str(), belief.predicate.c_str(),
           belief.confidence * 100);
    
    return stored.id;
}

bool WorldModel::updateBelief(uint64_t beliefId, float newConfidence,
                  const std::string& newEvidence,
                  bool isConfirmation) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = beliefs_.find(beliefId);
    if (it == beliefs_.end()) return false;
    
    auto& belief = it->second;
    belief.lastUpdatedMs = currentTimeMs();
    
    if (isConfirmation) {
        belief.confirmationCount++;
        if (!newEvidence.empty()) belief.evidence.push_back(newEvidence);
        
        // Bayesian-like update: confidence increases with confirmations
        float total = belief.confirmationCount + belief.refutationCount;
        if (total > 0) {
            float posterior = static_cast<float>(belief.confirmationCount) / total;
            // Blend with prior
            belief.confidence = belief.prior * 0.3f + posterior * 0.7f;
        }
        
        // Auto-confirm after 3+ confirmations
        if (belief.confirmationCount >= 3 && belief.confidence > 0.7f) {
            belief.status = Belief::Status::Confirmed;
        }
    } else {
        belief.refutationCount++;
        if (!newEvidence.empty()) belief.counterEvidence.push_back(newEvidence);
        
        // Reduce confidence
        float total = belief.confirmationCount + belief.refutationCount;
        if (total > 0) {
            float posterior = static_cast<float>(belief.confirmationCount) / total;
            belief.confidence = belief.prior * 0.3f + posterior * 0.7f;
        }
        
        // Auto-refute if strong counter-evidence
        if (belief.refutationCount >= 2 && belief.confidence < 0.3f) {
            belief.status = Belief::Status::Refuted;
        }
    }
    
    return true;
}

std::optional<Belief> WorldModel::getBelief(uint64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = beliefs_.find(id);
    if (it == beliefs_.end()) return std::nullopt;
    return it->second;
}

std::vector<Belief> WorldModel::getBeliefsBySubject(const std::string& subject) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Belief> result;
    for (const auto& [id, b] : beliefs_) {
        if (b.subject == subject && b.status == Belief::Status::Active) {
            result.push_back(b);
        }
    }
    return result;
}

std::vector<Belief> WorldModel::getConfirmedBeliefs() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Belief> result;
    for (const auto& [id, b] : beliefs_) {
        if (b.status == Belief::Status::Confirmed) {
            result.push_back(b);
        }
    }
    return result;
}

uint64_t WorldModel::createHypothesis(const Hypothesis& hyp) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto stored = hyp;
    stored.id = nextHypothesisId_++;
    stored.timestampMs = currentTimeMs();
    stored.status = Hypothesis::Status::Pending;
    
    hypotheses_[stored.id] = stored;
    
    printf("[WorldModel] New hypothesis: %s (conf %.0f%%)\n",
           hyp.statement.c_str(), hyp.confidence * 100);
    
    return stored.id;
}

bool WorldModel::testHypothesis(uint64_t hypId, const std::string& result,
                    bool confirmed) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = hypotheses_.find(hypId);
    if (it == hypotheses_.end()) return false;
    
    auto& hyp = it->second;
    hyp.testResult = result;
    hyp.status = confirmed ? Hypothesis::Status::Confirmed 
                            : Hypothesis::Status::Refuted;
    
    printf("[WorldModel] Hypothesis #%llu %s: %s\n",
           (unsigned long long)hypId,
           confirmed ? "CONFIRMED" : "REFUTED",
           result.c_str());
    
    // If confirmed → create/update belief
    if (confirmed) {
        addBelief({
            .id = 0,
            .subject = hyp.statement,
            .predicate = "confirmed",
            .value = hyp.testResult,
            .confidence = hyp.confidence,
            .prior = hyp.confidence,
            .evidence = {result},
            .counterEvidence = {},
            .timestampMs = 0,
            .lastUpdatedMs = 0,
            .status = Belief::Status::Confirmed,
            .source = "hypothesis_test",
            .confirmationCount = 1,
            .refutationCount = 0
        });
    }
    
    return true;
}

std::vector<Hypothesis> WorldModel::getPendingHypotheses() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Hypothesis> result;
    for (const auto& [id, h] : hypotheses_) {
        if (h.status == Hypothesis::Status::Pending ||
            h.status == Hypothesis::Status::Testing) {
            result.push_back(h);
        }
    }
    return result;
}

WorldModel::ReasoningResult WorldModel::reason(const std::string& query) {
    ReasoningResult result;
    result.confidence = 0.5f;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find beliefs related to the query
    std::vector<Belief> relevant;
    for (const auto& [id, b] : beliefs_) {
        if (b.subject.find(query) != std::string::npos ||
            b.predicate.find(query) != std::string::npos ||
            b.value.find(query) != std::string::npos) {
            if (b.status != Belief::Status::Refuted &&
                b.status != Belief::Status::Deprecated) {
                relevant.push_back(b);
            }
        }
    }
    
    if (relevant.empty()) {
        result.conclusion = "No relevant beliefs found for: " + query;
        result.confidence = 0.3f;
        return result;
    }
    
    // Aggregate evidence
    float totalConfidence = 0.0f;
    float maxConfidence = 0.0f;
    
    for (const auto& b : relevant) {
        totalConfidence += b.confidence;
        maxConfidence = std::max(maxConfidence, b.confidence);
        
        for (const auto& e : b.evidence) {
            result.supportingEvidence.push_back(e);
        }
        for (const auto& e : b.counterEvidence) {
            result.counterEvidence.push_back(e);
        }
    }
    
    // Weighted conclusion
    float avgConfidence = totalConfidence / relevant.size();
    result.confidence = (maxConfidence + avgConfidence) / 2.0f;
    
    // Find the highest-confidence belief as conclusion
    const Belief* best = nullptr;
    for (const auto& b : relevant) {
        if (!best || b.confidence > best->confidence) {
            best = &b;
        }
    }
    
    if (best) {
        result.conclusion = best->subject + " " + best->predicate +
            ": " + best->value;
        result.reasoning = "Based on " + std::to_string(relevant.size()) +
            " beliefs, " + std::to_string(result.supportingEvidence.size()) +
            " evidence items, confidence " +
            std::to_string(static_cast<int>(result.confidence * 100)) + "%";
    }
    
    return result;
}

size_t WorldModel::getBeliefCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, b] : beliefs_) {
        if (b.status != Belief::Status::Deprecated) count++;
    }
    return count;
}

size_t WorldModel::getConfirmedCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [id, b] : beliefs_) {
        if (b.status == Belief::Status::Confirmed) count++;
    }
    return count;
}

void WorldModel::createDefaultBeliefs() {
    // Initial beliefs about the analysis environment
    addBelief({
        .id = 0, .subject = "environment", .predicate = "is_sandbox",
        .value = "false", .confidence = 0.7f, .prior = 0.7f,
        .evidence = {"sandbox_check_passed"},
        .counterEvidence = {}, .timestampMs = 0, .lastUpdatedMs = 0,
        .status = Belief::Status::Active, .source = "system",
        .confirmationCount = 0, .refutationCount = 0
    });
    
    addBelief({
        .id = 0, .subject = "binary", .predicate = "is_analyzed",
        .value = "false", .confidence = 1.0f, .prior = 1.0f,
        .evidence = {"no_findings_yet"},
        .counterEvidence = {}, .timestampMs = 0, .lastUpdatedMs = 0,
        .status = Belief::Status::Active, .source = "system",
        .confirmationCount = 0, .refutationCount = 0
    });
}

uint64_t WorldModel::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

} // namespace RawrXD::Executive
