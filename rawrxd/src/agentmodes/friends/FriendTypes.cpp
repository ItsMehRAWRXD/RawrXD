// FriendTypes.cpp — RAWRXD_PHONE_A_FRIEND_001
#include "agentmodes/friends/FriendTypes.h"

namespace rawrxd { namespace friendx {

const char* toString(FriendAction a) {
    switch (a) {
        case FriendAction::Ask:       return "ASK";
        case FriendAction::FollowUp:  return "FOLLOW_UP";
        case FriendAction::Challenge: return "CHALLENGE";
        case FriendAction::Verify:    return "VERIFY";
        case FriendAction::Compare:   return "COMPARE";
        case FriendAction::Consensus: return "CONSENSUS";
    }
    return "ASK";
}

const char* toString(FriendProviderKind k) {
    switch (k) {
        case FriendProviderKind::Browser:          return "browser";
        case FriendProviderKind::LocalModel:       return "local";
        case FriendProviderKind::OpenAICompatible: return "openai_compatible";
        case FriendProviderKind::Human:            return "human";
    }
    return "unknown";
}

const char* toString(AdvisoryOutcome o) {
    switch (o) {
        case AdvisoryOutcome::Unavailable:       return "UNAVAILABLE";
        case AdvisoryOutcome::Pending:           return "PENDING";
        case AdvisoryOutcome::Accepted:          return "ACCEPTED";
        case AdvisoryOutcome::Rejected:          return "REJECTED";
        case AdvisoryOutcome::NeedsClarification:return "NEEDS_CLARIFICATION";
    }
    return "UNAVAILABLE";
}

}} // namespace rawrxd::friendx
