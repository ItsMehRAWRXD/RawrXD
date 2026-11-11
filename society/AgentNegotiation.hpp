#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Sovereign {
namespace Society {

struct NegotiationOffer {
    std::string offerId;
    std::string fromAgent;
    std::string toAgent;
    std::string resourceType;
    float quantity;
    std::string terms;
    int64_t expiresAt;
    bool isActive;
};

struct NegotiationSession {
    std::string sessionId;
    std::string initiator;
    std::string responder;
    std::string status;
    std::vector<std::string> offerIds;
    int64_t startedAt;
    int64_t lastActivity;
    bool isActive;
};

struct NegotiationOutcome {
    std::string outcomeId;
    std::string sessionId;
    std::string result;
    std::string terms;
    int64_t concludedAt;
    bool isHonored;
};

class AgentNegotiation {
public:
    static void Init();
    static void OnTick();
    static bool IsAlive();

    static std::string StartSession(const std::string& initiator, const std::string& responder);
    static bool EndSession(const std::string& sessionId);
    
    static std::string MakeOffer(const std::string& sessionId, 
                                  const std::string& fromAgent,
                                  const std::string& toAgent,
                                  const std::string& resourceType,
                                  float quantity,
                                  const std::string& terms,
                                  int64_t durationMs);
    static bool AcceptOffer(const std::string& offerId);
    static bool RejectOffer(const std::string& offerId);
    static bool CounterOffer(const std::string& originalOfferId,
                              float newQuantity,
                              const std::string& newTerms);
    
    static void RecordOutcome(const std::string& sessionId,
                              const std::string& result,
                              const std::string& terms);
    static void MarkOutcomeHonored(const std::string& outcomeId);
    
    static nlohmann::json GetSession(const std::string& sessionId);
    static nlohmann::json GetAgentSessions(const std::string& agentId);
    static nlohmann::json GetOffer(const std::string& offerId);
    static nlohmann::json GetSessionOffers(const std::string& sessionId);
    static nlohmann::json GetOutcome(const std::string& outcomeId);
    
    static nlohmann::json GetNegotiationMetrics();
    static nlohmann::json GetTrustNetwork();

private:
    static std::vector<NegotiationSession> s_sessions;
    static std::vector<NegotiationOffer> s_offers;
    static std::vector<NegotiationOutcome> s_outcomes;
    static std::mutex s_mutex;
    static bool s_alive;
    
    static NegotiationSession* FindSession(const std::string& sessionId);
    static NegotiationOffer* FindOffer(const std::string& offerId);
    static NegotiationOutcome* FindOutcome(const std::string& outcomeId);
};

} // namespace Society
} // namespace Sovereign
} // namespace RawrXD
