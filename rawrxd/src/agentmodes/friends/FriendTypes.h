// FriendTypes.h — RAWRXD_PHONE_A_FRIEND_001
// Shared vocabulary for external advisory consultation.
//
// THE ARCHITECTURAL RULE:
//     The friend advises. RawrXD retains authority.
//
// A friend response carries claims, recommendations and uncertainties. It
// deliberately carries NO verdict field, because an external model must never
// be able to mint a RawrXD certification result. A verdict can only be
// produced by the local authority, from local evidence.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace rawrxd { namespace friendx {

enum class FriendAction {
    Ask,
    FollowUp,
    Challenge,
    Verify,
    Compare,
    Consensus
};

enum class FriendProviderKind {
    Browser,
    LocalModel,
    OpenAICompatible,
    Human
};

const char* toString(FriendAction a);
const char* toString(FriendProviderKind k);

struct FriendRequest {
    FriendAction action = FriendAction::Ask;
    std::string  objective;       // what we are actually trying to decide
    std::string  question;        // the question put to the friend
    std::string  context;         // local context, already redacted
    std::string  evidence;        // observed evidence, already redacted
    std::string  conversationId;

    bool     allowFollowUps = true;
    uint32_t maxTurns       = 4;
};

struct FriendResponse {
    bool        success = false;
    std::string provider;          // provider name
    std::string model;             // model identity as reported
    std::string conversationId;
    std::string answer;            // raw text, recorded verbatim

    std::vector<std::string> claims;           // extracted assertions
    std::vector<std::string> recommendations;  // proposed actions
    std::vector<std::string> uncertainties;    // what the friend is unsure of

    uint32_t    turn    = 0;
    uint32_t    turnLimit = 0;
    std::string transport;         // how it was actually reached
    std::string unavailableReason; // non-empty when success == false
};

// The single stable provider interface. Replacing a transport must not change
// PhoneAFriendAuthority, so this is the only surface it depends on.
class IFriendProvider {
public:
    virtual ~IFriendProvider() = default;
    virtual const char* name() const = 0;
    virtual FriendProviderKind kind() const = 0;

    // Whether this provider can actually be reached right now. A provider
    // with no transport must return false and say why; it must never pretend.
    virtual bool available() const = 0;
    virtual std::string unavailableReason() const = 0;

    virtual FriendResponse ask(const FriendRequest& request) = 0;
};

// How the local authority treated a friend's advice. This is the only place
// an accept/reject decision may live, and it is always LOCAL.
enum class AdvisoryOutcome {
    Unavailable,      // could not reach a friend
    Pending,          // advice received, not yet judged
    Accepted,         // advice corroborated by local evidence
    Rejected,         // advice contradicted by local evidence
    NeedsClarification // advice insufficient; a follow-up is warranted
};

const char* toString(AdvisoryOutcome o);

struct AdvisoryAssessment {
    AdvisoryOutcome outcome = AdvisoryOutcome::Unavailable;
    std::string     reason;
    uint32_t        corroborated = 0;
    uint32_t        contradicted = 0;
    uint32_t        unverifiable = 0;
    // Advice is retained verbatim but never promoted to a verdict.
    std::vector<std::string> retainedClaims;
};

}} // namespace rawrxd::friendx
