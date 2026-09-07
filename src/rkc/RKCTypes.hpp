// RKCTypes.hpp — Reverse Knowledge Compiler IR
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace RKC {

enum class EpistemicState : uint8_t {
    Unknown = 0,
    Real,        // observation only
    Derived,     // deterministic from Real/Derived parents
    Synthetic,   // gap fill, unvalidated
    Inferred,    // hypothesis
    Conflict,    // competing Real
    Invalid,     // failed validation
    NotPresent,  // negative knowledge
    NotSupported,
    NotConnected,
    NotReachable,
    NotObserved,
    NotActive,   // present in tree but not armed/live
};

inline bool IsNegativeKnowledge(EpistemicState s) {
    return s == EpistemicState::NotPresent || s == EpistemicState::NotSupported ||
           s == EpistemicState::NotConnected || s == EpistemicState::NotReachable ||
           s == EpistemicState::NotObserved || s == EpistemicState::NotActive;
}

enum class AtomKind : uint8_t {
    Fact = 1,
    Constraint,
    Requirement,
    Negative,
};

struct KnowledgeAtom {
    std::string key;
    std::string value;
    EpistemicState state = EpistemicState::Unknown;
    AtomKind kind = AtomKind::Fact;
    std::vector<std::string> parents; // for Derived provenance
    std::string source;               // observer / recipe id
};

struct GoalNode {
    std::string key;
    std::vector<std::string> requiresKeys;
};

struct Recipe {
    std::string id;
    std::string producesKey;          // DERIVED key on success
    std::vector<std::string> needKeys;
    // Evaluated by GapEngine/Recipes; true → promote to Derived
};

struct ProofState {
    std::string goal;
    std::string task;
    std::vector<KnowledgeAtom> known;
    std::vector<KnowledgeAtom> missing;
    std::vector<KnowledgeAtom> negative;
    std::vector<std::string> constraints;
    std::vector<std::string> syntheticCandidates; // not promoted
};

inline const char* EpistemicName(EpistemicState s) {
    switch (s) {
    case EpistemicState::Real: return "REAL";
    case EpistemicState::Derived: return "DERIVED";
    case EpistemicState::Synthetic: return "SYNTHETIC";
    case EpistemicState::Inferred: return "INFERRED";
    case EpistemicState::Conflict: return "CONFLICT";
    case EpistemicState::Invalid: return "INVALID";
    case EpistemicState::NotPresent: return "NOT_PRESENT";
    case EpistemicState::NotSupported: return "NOT_SUPPORTED";
    case EpistemicState::NotConnected: return "NOT_CONNECTED";
    case EpistemicState::NotReachable: return "NOT_REACHABLE";
    case EpistemicState::NotObserved: return "NOT_OBSERVED";
    case EpistemicState::NotActive: return "NOT_ACTIVE";
    default: return "UNKNOWN";
    }
}

} // namespace RKC
} // namespace RawrXD
