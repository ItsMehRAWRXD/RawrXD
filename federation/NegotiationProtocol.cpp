#include "federation/NegotiationProtocol.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct Negotiation {
    std::string id;
    std::string from;
    std::string to;
    nlohmann::json proposal;
    nlohmann::json counter;
    std::string status; // pending, accepted, rejected
    int64_t createdAt;
    int64_t resolvedAt;
};

static std::map<std::string, Negotiation> s_negotiations;
static size_t s_negotiationCounter = 0;

static std::string GenerateNegotiationId() {
    s_negotiationCounter++;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "neg-" + std::to_string(now) + "-" + std::to_string(s_negotiationCounter);
}

void NegotiationProtocol::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_negotiations.clear();
        s_negotiationCounter = 0;
        s_initialized = true;
    }
}

void NegotiationProtocol::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Clean up old negotiations
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::vector<std::string> toRemove;
    for (const auto& [id, neg] : s_negotiations) {
        if (neg.status != "pending" && (now - neg.resolvedAt) > 3600000000000) { // 1 hour
            toRemove.push_back(id);
        }
    }
    for (const auto& id : toRemove) {
        s_negotiations.erase(id);
    }
}

bool NegotiationProtocol::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json NegotiationProtocol::Propose(const std::string& from, const std::string& to, const nlohmann::json& proposal) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    std::string id = GenerateNegotiationId();
    
    Negotiation neg;
    neg.id = id;
    neg.from = from;
    neg.to = to;
    neg.proposal = proposal;
    neg.status = "pending";
    neg.createdAt = std::chrono::system_clock::now().time_since_epoch().count();
    
    s_negotiations[id] = neg;
    
    return {
        {"negotiation_id", id},
        {"status", "pending"},
        {"from", from},
        {"to", to}
    };
}

nlohmann::json NegotiationProtocol::Respond(const std::string& negotiationId, bool accepted, const nlohmann::json& counter) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto it = s_negotiations.find(negotiationId);
    if (it != s_negotiations.end()) {
        it->second.status = accepted ? "accepted" : "rejected";
        it->second.counter = counter;
        it->second.resolvedAt = std::chrono::system_clock::now().time_since_epoch().count();
        
        return {
            {"negotiation_id", negotiationId},
            {"status", it->second.status},
            {"accepted", accepted}
        };
    }
    
    return {
        {"error", "negotiation_not_found"},
        {"negotiation_id", negotiationId}
    };
}

nlohmann::json NegotiationProtocol::GetNegotiation(const std::string& negotiationId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_negotiations.find(negotiationId);
    if (it != s_negotiations.end()) {
        return {
            {"id", it->second.id},
            {"from", it->second.from},
            {"to", it->second.to},
            {"proposal", it->second.proposal},
            {"status", it->second.status},
            {"created_at", it->second.createdAt}
        };
    }
    return nlohmann::json{};
}

nlohmann::json NegotiationProtocol::GetActiveNegotiations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, neg] : s_negotiations) {
        if (neg.status == "pending") {
            result.push_back({
                {"id", neg.id},
                {"from", neg.from},
                {"to", neg.to},
                {"created_at", neg.createdAt}
            });
        }
    }
    return result;
}

nlohmann::json NegotiationProtocol::GetNegotiationHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, neg] : s_negotiations) {
        if (neg.status != "pending") {
            result.push_back({
                {"id", neg.id},
                {"from", neg.from},
                {"to", neg.to},
                {"status", neg.status},
                {"resolved_at", neg.resolvedAt}
            });
        }
    }
    return result;
}

nlohmann::json NegotiationProtocol::GetNegotiationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t pendingCount = 0;
    size_t acceptedCount = 0;
    size_t rejectedCount = 0;
    
    for (const auto& [id, neg] : s_negotiations) {
        if (neg.status == "pending") pendingCount++;
        else if (neg.status == "accepted") acceptedCount++;
        else if (neg.status == "rejected") rejectedCount++;
    }
    
    return {
        {"total_negotiations", s_negotiations.size()},
        {"pending", pendingCount},
        {"accepted", acceptedCount},
        {"rejected", rejectedCount}
    };
}
