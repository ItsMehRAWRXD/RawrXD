#include "society/AgentNegotiation.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Sovereign {
namespace Society {

std::vector<NegotiationSession> AgentNegotiation::s_sessions;
std::vector<NegotiationOffer> AgentNegotiation::s_offers;
std::vector<NegotiationOutcome> AgentNegotiation::s_outcomes;
std::mutex AgentNegotiation::s_mutex;
bool AgentNegotiation::s_alive = false;

void AgentNegotiation::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_sessions.clear();
    s_offers.clear();
    s_outcomes.clear();
    s_alive = true;
}

void AgentNegotiation::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_alive) return;
    
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    
    // Expire old offers
    for (auto& offer : s_offers) {
        if (offer.isActive && now > offer.expiresAt) {
            offer.isActive = false;
        }
    }
    
    // Update session activity timeouts
    for (auto& session : s_sessions) {
        if (session.isActive && (now - session.lastActivity) > 3600000000000LL) { // 1 hour
            session.isActive = false;
            session.status = "timeout";
        }
    }
}

bool AgentNegotiation::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_alive;
}

std::string AgentNegotiation::StartSession(const std::string& initiator, const std::string& responder) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationSession session;
    session.sessionId = "session_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    session.initiator = initiator;
    session.responder = responder;
    session.status = "active";
    session.startedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    session.lastActivity = session.startedAt;
    session.isActive = true;
    
    s_sessions.push_back(session);
    return session.sessionId;
}

bool AgentNegotiation::EndSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationSession* session = FindSession(sessionId);
    if (!session) return false;
    
    session->isActive = false;
    session->status = "ended";
    return true;
}

std::string AgentNegotiation::MakeOffer(const std::string& sessionId, 
                                         const std::string& fromAgent,
                                         const std::string& toAgent,
                                         const std::string& resourceType,
                                         float quantity,
                                         const std::string& terms,
                                         int64_t durationMs) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationSession* session = FindSession(sessionId);
    if (!session) return "";
    
    NegotiationOffer offer;
    offer.offerId = "offer_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    offer.fromAgent = fromAgent;
    offer.toAgent = toAgent;
    offer.resourceType = resourceType;
    offer.quantity = quantity;
    offer.terms = terms;
    offer.expiresAt = std::chrono::steady_clock::now().time_since_epoch().count() + durationMs;
    offer.isActive = true;
    
    s_offers.push_back(offer);
    session->offerIds.push_back(offer.offerId);
    session->lastActivity = std::chrono::steady_clock::now().time_since_epoch().count();
    
    return offer.offerId;
}

bool AgentNegotiation::AcceptOffer(const std::string& offerId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationOffer* offer = FindOffer(offerId);
    if (!offer || !offer->isActive) return false;
    
    offer->isActive = false;
    
    // Update session
    for (auto& session : s_sessions) {
        if (std::find(session.offerIds.begin(), session.offerIds.end(), offerId) != session.offerIds.end()) {
            session.lastActivity = std::chrono::steady_clock::now().time_since_epoch().count();
            break;
        }
    }
    
    return true;
}

bool AgentNegotiation::RejectOffer(const std::string& offerId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationOffer* offer = FindOffer(offerId);
    if (!offer || !offer->isActive) return false;
    
    offer->isActive = false;
    
    // Update session
    for (auto& session : s_sessions) {
        if (std::find(session.offerIds.begin(), session.offerIds.end(), offerId) != session.offerIds.end()) {
            session.lastActivity = std::chrono::steady_clock::now().time_since_epoch().count();
            break;
        }
    }
    
    return true;
}

bool AgentNegotiation::CounterOffer(const std::string& originalOfferId,
                                     float newQuantity,
                                     const std::string& newTerms) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationOffer* original = FindOffer(originalOfferId);
    if (!original || !original->isActive) return false;
    
    // Create counter offer
    NegotiationOffer counter;
    counter.offerId = "offer_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    counter.fromAgent = original->toAgent;
    counter.toAgent = original->fromAgent;
    counter.resourceType = original->resourceType;
    counter.quantity = newQuantity;
    counter.terms = newTerms;
    counter.expiresAt = std::chrono::steady_clock::now().time_since_epoch().count() + 300000000000LL; // 5 min
    counter.isActive = true;
    
    s_offers.push_back(counter);
    
    // Update session
    for (auto& session : s_sessions) {
        if (std::find(session.offerIds.begin(), session.offerIds.end(), originalOfferId) != session.offerIds.end()) {
            session.offerIds.push_back(counter.offerId);
            session.lastActivity = std::chrono::steady_clock::now().time_since_epoch().count();
            break;
        }
    }
    
    return true;
}

void AgentNegotiation::RecordOutcome(const std::string& sessionId,
                                      const std::string& result,
                                      const std::string& terms) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationOutcome outcome;
    outcome.outcomeId = "outcome_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    outcome.sessionId = sessionId;
    outcome.result = result;
    outcome.terms = terms;
    outcome.concludedAt = std::chrono::steady_clock::now().time_since_epoch().count();
    outcome.isHonored = false;
    
    s_outcomes.push_back(outcome);
    
    // Update session
    NegotiationSession* session = FindSession(sessionId);
    if (session) {
        session->status = result;
        session->isActive = false;
    }
}

void AgentNegotiation::MarkOutcomeHonored(const std::string& outcomeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationOutcome* outcome = FindOutcome(outcomeId);
    if (outcome) {
        outcome->isHonored = true;
    }
}

nlohmann::json AgentNegotiation::GetSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationSession* session = FindSession(sessionId);
    if (!session) return nlohmann::json{{"error", "session not found"}};
    
    nlohmann::json j;
    j["sessionId"] = session->sessionId;
    j["initiator"] = session->initiator;
    j["responder"] = session->responder;
    j["status"] = session->status;
    j["startedAt"] = session->startedAt;
    j["lastActivity"] = session->lastActivity;
    j["isActive"] = session->isActive;
    j["offerCount"] = session->offerIds.size();
    return j;
}

nlohmann::json AgentNegotiation::GetAgentSessions(const std::string& agentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json sessions = nlohmann::json::array();
    for (const auto& session : s_sessions) {
        if (session.initiator == agentId || session.responder == agentId) {
            nlohmann::json j;
            j["sessionId"] = session.sessionId;
            j["status"] = session.status;
            j["isActive"] = session.isActive;
            j["otherParty"] = (session.initiator == agentId) ? session.responder : session.initiator;
            sessions.push_back(j);
        }
    }
    return sessions;
}

nlohmann::json AgentNegotiation::GetOffer(const std::string& offerId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationOffer* offer = FindOffer(offerId);
    if (!offer) return nlohmann::json{{"error", "offer not found"}};
    
    nlohmann::json j;
    j["offerId"] = offer->offerId;
    j["fromAgent"] = offer->fromAgent;
    j["toAgent"] = offer->toAgent;
    j["resourceType"] = offer->resourceType;
    j["quantity"] = offer->quantity;
    j["terms"] = offer->terms;
    j["expiresAt"] = offer->expiresAt;
    j["isActive"] = offer->isActive;
    return j;
}

nlohmann::json AgentNegotiation::GetSessionOffers(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationSession* session = FindSession(sessionId);
    if (!session) return nlohmann::json{{"error", "session not found"}};
    
    nlohmann::json offers = nlohmann::json::array();
    for (const auto& offerId : session->offerIds) {
        NegotiationOffer* offer = FindOffer(offerId);
        if (offer) {
            nlohmann::json j;
            j["offerId"] = offer->offerId;
            j["fromAgent"] = offer->fromAgent;
            j["resourceType"] = offer->resourceType;
            j["quantity"] = offer->quantity;
            j["isActive"] = offer->isActive;
            offers.push_back(j);
        }
    }
    return offers;
}

nlohmann::json AgentNegotiation::GetOutcome(const std::string& outcomeId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    NegotiationOutcome* outcome = FindOutcome(outcomeId);
    if (!outcome) return nlohmann::json{{"error", "outcome not found"}};
    
    nlohmann::json j;
    j["outcomeId"] = outcome->outcomeId;
    j["sessionId"] = outcome->sessionId;
    j["result"] = outcome->result;
    j["terms"] = outcome->terms;
    j["concludedAt"] = outcome->concludedAt;
    j["isHonored"] = outcome->isHonored;
    return j;
}

nlohmann::json AgentNegotiation::GetNegotiationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json metrics;
    metrics["totalSessions"] = s_sessions.size();
    metrics["totalOffers"] = s_offers.size();
    metrics["totalOutcomes"] = s_outcomes.size();
    
    size_t activeSessions = 0;
    size_t successfulOutcomes = 0;
    size_t honoredOutcomes = 0;
    
    for (const auto& session : s_sessions) {
        if (session.isActive) activeSessions++;
    }
    
    for (const auto& outcome : s_outcomes) {
        if (outcome.result == "success") successfulOutcomes++;
        if (outcome.isHonored) honoredOutcomes++;
    }
    
    metrics["activeSessions"] = activeSessions;
    metrics["successfulOutcomes"] = successfulOutcomes;
    metrics["honoredOutcomes"] = honoredOutcomes;
    metrics["successRate"] = s_outcomes.empty() ? 0.0f : (float)successfulOutcomes / s_outcomes.size();
    metrics["honorRate"] = s_outcomes.empty() ? 0.0f : (float)honoredOutcomes / s_outcomes.size();
    
    return metrics;
}

nlohmann::json AgentNegotiation::GetTrustNetwork() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Build trust network based on honored outcomes
    std::map<std::pair<std::string, std::string>, int> trustScores;
    
    for (const auto& outcome : s_outcomes) {
        if (outcome.isHonored) {
            NegotiationSession* session = FindSession(outcome.sessionId);
            if (session) {
                auto key = std::make_pair(session->initiator, session->responder);
                trustScores[key]++;
            }
        }
    }
    
    nlohmann::json network = nlohmann::json::array();
    for (const auto& [pair, score] : trustScores) {
        nlohmann::json edge;
        edge["from"] = pair.first;
        edge["to"] = pair.second;
        edge["trustScore"] = score;
        network.push_back(edge);
    }
    
    return network;
}

NegotiationSession* AgentNegotiation::FindSession(const std::string& sessionId) {
    for (auto& session : s_sessions) {
        if (session.sessionId == sessionId) return &session;
    }
    return nullptr;
}

NegotiationOffer* AgentNegotiation::FindOffer(const std::string& offerId) {
    for (auto& offer : s_offers) {
        if (offer.offerId == offerId) return &offer;
    }
    return nullptr;
}

NegotiationOutcome* AgentNegotiation::FindOutcome(const std::string& outcomeId) {
    for (auto& outcome : s_outcomes) {
        if (outcome.outcomeId == outcomeId) return &outcome;
    }
    return nullptr;
}

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
