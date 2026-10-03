// ============================================================================
// ReverseReceiptTradeTitan.hpp
//
// REVERSE_TRADE_TITAN_001 + REVERSE_RECEIPT_TRADE_TITAN_001
//
// Two authorities that share one structure, distinguished only by direction.
//
//   TRADE TITAN            rearranges STICKS so a STONE becomes executable
//   REVERSE TRADE TITAN    rearranges the REPRESENTATION of a STONE so the
//                          available STICKS can satisfy it
//
//   NORMAL RECEIPT         REALITY -> PASS      (evidence produces a verdict)
//   REVERSE RECEIPT        PASS -> REALITY      (a verdict must be walked back
//                                                into the physical facts that
//                                                would have to exist for it to
//                                                be true)
//
// THE LAW THIS FILE EXISTS TO ENFORCE
//
//   A PASS is not a source. It is a conclusion.
//
//   Therefore no PASS may stand alone. It must reverse, link by link, into
//   measured physical reality. If any link cannot be recovered, the verdict is
//   UNPROVEN. If any link is contradicted, the verdict is FAIL.
//
//   This repository has retracted three false PASS receipts. Every one of them
//   failed the same test this header implements: the verdict was printed but the
//   chain beneath it was not walkable.
//
//   A_DIAGNOSTIC_THAT_CANNOT_DISAGREE_IS_NOT_A_DIAGNOSTIC
//
// WHY REVERSE TITAN IS PERMITTED TO CHANGE THE STONE'S FORM
//
//   The guard is not "the requirement may be weakened". It is narrower and
//   checkable:
//
//     PHYSICAL_48_REPORTED_AS_PHYSICAL_96 = FORBIDDEN
//     PHYSICAL_48_EXPOSED_AS_LOGICAL_96 = ALLOWED
//     PASS_REQUIRES_REQUIRED_BEHAVIOR     = REQUIRED
//     PASS_REQUIRES_LITERAL_REPRESENTATION = NOT_REQUIRED
//
//   So a capacity requirement may be reversed from SIMULTANEOUS_RESIDENCY into
//   LOGICAL_ADDRESSABILITY only when the behaviour the workload actually
//   requires is measured. It may never be reversed by editing the number.
//
//   The dangerous case is named explicitly below: LOGICAL_ADDRESSABILITY with
//   no regeneration equivalence lets a 3B model masquerade as a 671B model. That
//   is why `LinkId::RegenerationEquivalence` exists as a REQUIRED link rather
//   than an optional one.
//
// NO VERDICT SETTER
//
//   There is no `markPass`, no `setVerdict`, no aggregate. Every verdict is
//   computed by `evaluate()` from per-link states that are themselves derived
//   from parsed evidence. A caller cannot assert success.
// ============================================================================

#ifndef RAWRXD_OPERATORS_REVERSE_RECEIPT_TRADE_TITAN_HPP
#define RAWRXD_OPERATORS_REVERSE_RECEIPT_TRADE_TITAN_HPP

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace RawrXD::Operators {

// ---------------------------------------------------------------------------
// Link identity
//
// Ordered from the claim (index 0) back to physical reality (last index).
// The chain is walked in this order. Order is explicit so a receipt cannot
// present a link out of sequence and still read as complete.
// ---------------------------------------------------------------------------
enum class LinkId : std::uint8_t {
    ClaimedVerdict = 0,   // PASS=1 is what the receipt asserts
    StoneOriginal,        // what was originally required
    StoneReversed,        // the requirement form actually used
    TradeApplied,         // which transformation made the fit possible
    ExecutionObserved,    // execution really ran
    OutputMeasuredNonZero,// a real output count, not a claimed one
    CallbacksObserved,    // streaming path really fired
    PhysicalSticksIdentified,   // WHICH HARDWARE ACTUALLY DID THE WORK
    ExecutionBackendNamed,      // WHICH ROUTE ACTUALLY FIRED
    ModelIdentityBound,         // WHICH MODEL ACTUALLY RAN
    RegenerationEquivalence,    // logical-vs-physical claim is proved, not asserted
    LinkCount
};

inline const char* linkName(LinkId id) noexcept {
    switch (id) {
        case LinkId::ClaimedVerdict:            return "CLAIMED_VERDICT";
        case LinkId::StoneOriginal:             return "STONE_ORIGINAL";
        case LinkId::StoneReversed:             return "STONE_REVERSED";
        case LinkId::TradeApplied:              return "TRADE_APPLIED";
        case LinkId::ExecutionObserved:         return "EXECUTION_OBSERVED";
        case LinkId::OutputMeasuredNonZero:     return "OUTPUT_MEASURED_NONZERO";
        case LinkId::CallbacksObserved:         return "CALLBACKS_OBSERVED";
        case LinkId::PhysicalSticksIdentified:  return "PHYSICAL_STICKS_IDENTIFIED";
        case LinkId::ExecutionBackendNamed:     return "EXECUTION_BACKEND_NAMED";
        case LinkId::ModelIdentityBound:        return "MODEL_IDENTITY_BOUND";
        case LinkId::RegenerationEquivalence:   return "REGENERATION_EQUIVALENCE";
        default:                                return "?";
    }
}

inline constexpr std::size_t kLinkCount =
    static_cast<std::size_t>(LinkId::LinkCount);

// Every link is mandatory. There is deliberately no "optional" link: an
// optional link in a reverse receipt is a hole the claim can fall through.
inline constexpr bool linkRequired(LinkId) noexcept { return true; }

// ---------------------------------------------------------------------------
// Per-link state
// ---------------------------------------------------------------------------
enum class LinkState : std::uint8_t {
    Missing = 0,      // nothing in the receipt addresses this link
    Recoverable,      // evidence present and internally consistent
    Contradicted      // evidence present and it disagrees with the claim
};

inline const char* linkStateName(LinkState s) noexcept {
    switch (s) {
        case LinkState::Missing:      return "MISSING";
        case LinkState::Recoverable:  return "RECOVERABLE";
        case LinkState::Contradicted: return "CONTRADICTED";
    }
    return "?";
}

struct ReverseLink {
    LinkId      id    = LinkId::ClaimedVerdict;
    LinkState   state = LinkState::Missing;
    // The literal receipt line that justifies `state`. Empty when Missing.
    // Populated by the parser, never by a verdict path.
    std::string evidence;
};

// ---------------------------------------------------------------------------
// Parsed evidence
//
// This is the ONLY input the reverse chain is allowed to consume. It is built
// by scanning literal `KEY=VALUE` receipt lines. It cannot be constructed with
// a verdict.
// ---------------------------------------------------------------------------
struct ParsedEvidence {
    // key -> every value seen for that key, in file order.
    std::map<std::string, std::vector<std::string>> fields;

    bool has(const std::string& key) const {
        return fields.find(key) != fields.end();
    }

    std::string first(const std::string& key) const {
        auto it = fields.find(key);
        if (it == fields.end() || it->second.empty()) return {};
        return it->second.front();
    }

    std::size_t count(const std::string& key) const {
        auto it = fields.find(key);
        return it == fields.end() ? 0u : it->second.size();
    }

    // True only when the key exists AND parses to a value strictly greater
    // than zero. Absence is not zero; absence is Missing.
    bool positive(const std::string& key) const {
        auto it = fields.find(key);
        if (it == fields.end() || it->second.empty()) return false;
        const std::string& v = it->second.front();
        if (v.empty()) return false;
        for (char c : v) {
            if (c < '0' || c > '9') return false;   // reject "-1", "1e9", "PASS"
        }
        // strip leading zeros then compare
        std::size_t i = 0;
        while (i + 1 < v.size() && v[i] == '0') ++i;
        return v[i] != '0';
    }

    bool isZero(const std::string& key) const {
        auto it = fields.find(key);
        if (it == fields.end() || it->second.empty()) return false;
        const std::string& v = it->second.front();
        if (v.empty()) return false;
        for (char c : v) {
            if (c < '0' || c > '9') return false;
        }
        std::size_t i = 0;
        while (i + 1 < v.size() && v[i] == '0') ++i;
        return v[i] == '0';
    }

    // True when the key exists AND its value actually NAMES something.
    //
    // Key presence alone is NOT evidence. The first version of this walk used
    // `has()` here, and a CPU-only run that recorded the literal placeholder
    // DEVICE=<none> reversed to PASS -- the placeholder was accepted as a
    // measured device name. A real falsification run exposed it. Receipts are
    // produced by many parties, so the consumer must refuse placeholders even
    // when a producer promises not to emit them.
    bool names(const std::string& key) const {
        auto it = fields.find(key);
        if (it == fields.end() || it->second.empty()) return false;
        const std::string& v = it->second.front();
        if (v.empty()) return false;
        return v != "<none>" && v != "<unset>"
            && v != "none" && v != "unset" && v != "UNKNOWN";
    }

    bool equals(const std::string& key, const char* want) const {
        return first(key) == want;
    }
};

// ---------------------------------------------------------------------------
// Reverse receipt
// ---------------------------------------------------------------------------
enum class ReverseVerdict : std::uint8_t {
    Unproven = 0,   // a required link could not be recovered
    Fail,           // a link was contradicted by the receipt's own evidence
    Pass            // every required link recovered, none contradicted
};

inline const char* reverseVerdictName(ReverseVerdict v) noexcept {
    switch (v) {
        case ReverseVerdict::Unproven: return "UNPROVEN";
        case ReverseVerdict::Fail:     return "FAIL";
        case ReverseVerdict::Pass:     return "PASS";
    }
    return "?";
}

struct ReverseReceipt {
    std::vector<ReverseLink> links;   // exactly kLinkCount entries, in order

    std::size_t recovered  = 0;
    std::size_t missing    = 0;
    std::size_t contradicted = 0;

    ReverseVerdict verdict    = ReverseVerdict::Unproven;
    bool           complete   = false;

    // Set when a link was found but its value disagrees with the claim. A
    // contradicted link is reported separately from a missing one because
    // "the receipt does not mention it" and "the receipt says otherwise" are
    // different failures and only one of them is falsification.
    std::vector<std::string> blockers;
};

// ---------------------------------------------------------------------------
// Receipt parser -- SHARED by the product and by any external verifier.
//
// It lives here, not in a driver, so the product can reverse-walk its OWN
// receipt. A verifier that lives only outside the product leaves the product
// free to emit a PASS nobody inside the binary ever checks, which is the gap
// this placement closes.
// ---------------------------------------------------------------------------
inline ParsedEvidence parseReceipt(const std::string& text) {
    ParsedEvidence ev;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string line = text.substr(pos, eol - pos);

        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        std::size_t b = 0;
        while (b < line.size() && (line[b] == ' ' || line[b] == '\t')) ++b;

        // A comment or a blank line is not a field. A line may carry SEVERAL
        // fields (the per-node records do), so this scans KEY=VALUE pairs
        // rather than treating the line as one pair.
        //
        // QUOTING. A value containing a space must survive intact, or a GPU
        // name round-trips as "AMD". Two attempts failed before this one:
        //
        //   (1) plain whitespace split  -> value truncated at the first space
        //   (2) quote-aware token split -> handled a quote only at TOKEN
        //       START, so EXECUTION_DEVICE="AMD Radeon..." yielded the value
        //       `"AMD` with an unbalanced quote
        //
        // and (2) additionally used `i <= size` with an `i > size` guard that
        // never fires at exactly size(), so the loop never terminated: the
        // product hung inside renderBowRainReceipt() and truncated a good
        // receipt to 0 bytes. The loop here is bounded by construction, and
        // writeBowRainReceipt() now renders BEFORE truncating so that even a
        // future fault here cannot destroy the artifact it verifies.
        //
        // So: read the key up to '=', then if the value opens with a quote read
        // to the CLOSING quote; otherwise read to the next space.
        if (b < line.size() && line[b] != '#' && line[b] != ';') {
            std::size_t i = b;
            while (i < line.size()) {
                const std::size_t eq = line.find('=', i);
                if (eq == std::string::npos) break;   // no field on this span

                const std::string key = line.substr(i, eq - i);
                std::string val;
                std::size_t next;

                if (eq + 1 < line.size() && line[eq + 1] == '"') {
                    const std::size_t close = line.find('"', eq + 2);
                    if (close == std::string::npos) {
                        // Unterminated: take the rest of the line verbatim
                        // rather than inventing a value or looping.
                        val = line.substr(eq + 1);
                        next = line.size();
                    } else {
                        val = line.substr(eq + 2, close - (eq + 2));
                        next = close + 1;
                    }
                } else {
                    std::size_t sp = line.find(' ', eq + 1);
                    if (sp == std::string::npos) sp = line.size();
                    val = line.substr(eq + 1, sp - (eq + 1));
                    next = sp;
                }

                if (!key.empty())
                    ev.fields[key].push_back(val);

                // Always advance past at least one character, so this loop
                // terminates on any input including malformed ones.
                i = (next > i) ? next : i + 1;
                while (i < line.size() && line[i] == ' ') ++i;
            }
        }
        if (eol >= text.size()) break;
        pos = eol + 1;
    }
    return ev;
}

// ---------------------------------------------------------------------------
// The authority
// ---------------------------------------------------------------------------
class ReverseReceiptTradeTitan {
public:
    // Walks the chain from the claimed verdict back to physical reality.
    //
    // No parameter can express a verdict. The only input is parsed evidence
    // read from a receipt, so a caller cannot assert a result -- it can only
    // supply the material the result is derived from.
    static ReverseReceipt reverse(const ParsedEvidence& ev) {
        ReverseReceipt r;
        r.links.reserve(kLinkCount);

        auto push = [&r](LinkId id, LinkState st, std::string ev_) {
            r.links.push_back(ReverseLink{id, st, std::move(ev_)});
            switch (st) {
                case LinkState::Recoverable:  ++r.recovered;     break;
                case LinkState::Missing:      ++r.missing;       break;
                case LinkState::Contradicted: ++r.contradicted;  break;
            }
        };

        // ---- LINK 0: does the receipt actually claim PASS? ----------------
        // A receipt that never claimed PASS cannot be reversed into a PASS.
        // That is not Unproven; it is simply "there was nothing to reverse".
        //
        // claimedPass is hoisted because a CONTRADICTION is only meaningful
        // relative to a claim. A receipt recording a zero measurement while
        // claiming nothing is reporting honestly, not contradicting itself.
        // The first version of this file tested the zero without the claim,
        // and the F4 falsification case caught it: an honest negative receipt
        // was reported as FAIL. That is the same defect class the repository
        // ledger warns about -- an instrument that disagrees for the wrong
        // reason is no better than one that cannot disagree at all.
        const bool claimedPass =
            ev.equals("CERTIFICATION_VERDICT", "PASS") ||
            ev.equals("RUNTIME_VERDICT", "PASS") ||
            ev.equals("VERDICT", "PASS");

        if (claimedPass) {
            push(LinkId::ClaimedVerdict, LinkState::Recoverable,
                 "CERTIFICATION_VERDICT=PASS");
        } else {
            push(LinkId::ClaimedVerdict, LinkState::Missing, {});
        }

        // ---- LINK 1: the original stone -------------------------------------
        // What was required before any reversal. A receipt that reverses a
        // requirement without recording the original is asserting a
        // transformation it cannot be checked against.
        if (ev.names("ORIGINAL_STONE") || ev.names("STONE_ORIGINAL") || ev.names("MODEL_REQUIRES") || ev.names("REQUIREMENT_ORIGINAL")) {
            push(LinkId::StoneOriginal, LinkState::Recoverable,
                 ev.has("ORIGINAL_STONE") ? "ORIGINAL_STONE"
                                          : "STONE_ORIGINAL");
        } else {
            push(LinkId::StoneOriginal, LinkState::Missing, {});
        }

        // ---- LINK 2: the reversed stone ------------------------------------
        if (ev.names("REVERSED_REQUIREMENT") || ev.names("STONE_REVERSED") || ev.names("REQUIREMENT_FORM_USED")) {
            push(LinkId::StoneReversed, LinkState::Recoverable,
                 ev.has("REVERSED_REQUIREMENT") ? "REVERSED_REQUIREMENT"
                                                 : "STONE_REVERSED");
        } else {
            push(LinkId::StoneReversed, LinkState::Missing, {});
        }

        // ---- LINK 3: the trade ---------------------------------------------
        if (ev.names("TRADE_KIND") || ev.names("TRADE_APPLIED")) {
            push(LinkId::TradeApplied, LinkState::Recoverable,
                 ev.has("TRADE_KIND") ? "TRADE_KIND" : "TRADE_APPLIED");
        } else {
            push(LinkId::TradeApplied, LinkState::Missing, {});
        }

        // ---- LINK 4: execution really ran ----------------------------------
        // EXECUTION_EVIDENCE_RECORDED is the receipt's own assertion. It is
        // only accepted together with a strictly positive measured count below;
        // on its own it is a claim, which is precisely what this chain exists
        // to refuse.
        if (ev.positive("EXECUTION_EVIDENCE_RECORDED")) {
            push(LinkId::ExecutionObserved, LinkState::Recoverable,
                 "EXECUTION_EVIDENCE_RECORDED=1");
        } else {
            push(LinkId::ExecutionObserved, LinkState::Missing, {});
        }

        // ---- LINK 5: a real output count -----------------------------------
        if (ev.positive("MEASURED_OUTPUT_COUNT")) {
            push(LinkId::OutputMeasuredNonZero, LinkState::Recoverable,
                 "MEASURED_OUTPUT_COUNT=" + ev.first("MEASURED_OUTPUT_COUNT"));
        } else if (ev.has("MEASURED_OUTPUT_COUNT") && claimedPass) {
            // Present, zero, AND the receipt claims PASS. That is the exact
            // shape of the retracted false receipts in this repository.
            // Without a claim there is nothing to contradict.
            push(LinkId::OutputMeasuredNonZero, LinkState::Contradicted,
                 "MEASURED_OUTPUT_COUNT=" + ev.first("MEASURED_OUTPUT_COUNT") +
                 " while CERTIFICATION_VERDICT=PASS");
        } else if (ev.has("MEASURED_OUTPUT_COUNT")) {
            // Measured zero with no claim: honest, and recorded as such.
            push(LinkId::OutputMeasuredNonZero, LinkState::Missing,
                 "MEASURED_OUTPUT_COUNT=" + ev.first("MEASURED_OUTPUT_COUNT") +
                 " (no PASS claimed)");
        } else {
            push(LinkId::OutputMeasuredNonZero, LinkState::Missing, {});
        }

        // ---- LINK 6: the streaming path fired ------------------------------
        if (ev.positive("CALLBACKS_OBSERVED")) {
            push(LinkId::CallbacksObserved, LinkState::Recoverable,
                 "CALLBACKS_OBSERVED=" + ev.first("CALLBACKS_OBSERVED"));
        } else {
            push(LinkId::CallbacksObserved, LinkState::Missing, {});
        }

        // ---- LINK 7: which hardware actually did the work ------------------
        // This is the link whose absence produced the refusal to certify the
        // GPU in this repository before ENABLE_VULKAN was distinguished from
        // GPU_WEIGHT_RESIDENCY. A PASS that cannot name the physical means
        // that satisfied it is not a PASS, it is a hope.
        if (ev.names("EXECUTION_DEVICE") || ev.names("PHYSICAL_STICKS") || ev.names("GPU_DEVICE") || ev.names("EXECUTION_HARDWARE")) {
            push(LinkId::PhysicalSticksIdentified, LinkState::Recoverable,
                 ev.first("EXECUTION_DEVICE"));
        } else {
            push(LinkId::PhysicalSticksIdentified, LinkState::Missing, {});
        }

        // ---- LINK 8: which route fired -------------------------------------
        if (ev.names("EXECUTION_BACKEND") || ev.names("EXECUTION_RETURN_SITE")) {
            push(LinkId::ExecutionBackendNamed, LinkState::Recoverable,
                 ev.first("EXECUTION_BACKEND"));
        } else {
            push(LinkId::ExecutionBackendNamed, LinkState::Missing, {});
        }

        // ---- LINK 9: which model actually ran ------------------------------
        if (ev.names("MODEL_IDENTITY") || ev.names("MODEL_FINGERPRINT") || ev.names("MODEL_PATH") || ev.names("MODEL_SHA256")) {
            push(LinkId::ModelIdentityBound, LinkState::Recoverable,
                 ev.first("MODEL_IDENTITY"));
        } else {
            push(LinkId::ModelIdentityBound, LinkState::Missing, {});
        }

        // ---- LINK 10: is the logical claim proved, or only declared? -------
        // If the receipt reversed a capacity requirement, the equivalence
        // between the logical space and the physical window must be measured.
        // Without it, "48 GB exposed as 96 GB" is indistinguishable from a
        // model pretending to be larger than it is.
        if (ev.positive("REGEN_EQUIVALENCE_PROVED") ||
            ev.positive("REQUIREMENT_BEHAVIOR_SATISFIED")) {
            push(LinkId::RegenerationEquivalence, LinkState::Recoverable,
                 "REQUIREMENT_BEHAVIOR_SATISFIED=1");
        } else {
            push(LinkId::RegenerationEquivalence, LinkState::Missing, {});
        }

        // ---- DERIVE --------------------------------------------------------
        // No branch above can set the verdict. It is computed only here, only
        // from the per-link counts.
        r.complete = (r.missing == 0) && (r.contradicted == 0);

        if (r.contradicted > 0) {
            r.verdict = ReverseVerdict::Fail;
            r.blockers.push_back("CONTRADICTED_LINK_PRESENT");
        } else if (r.missing > 0) {
            r.verdict = ReverseVerdict::Unproven;
            for (const auto& l : r.links) {
                if (l.state == LinkState::Missing) {
                    r.blockers.push_back(std::string("MISSING_LINK:") + linkName(l.id));
                }
            }
        } else {
            r.verdict = ReverseVerdict::Pass;
        }
        return r;
    }

    // Normal receipt direction, for contrast. Kept so the two directions can
    // be compared by the probe rather than by assertion.
    static std::size_t forwardEvidenceCount(const ParsedEvidence& ev) {
        return ev.fields.size();
    }
};

// ---------------------------------------------------------------------------
// THE HARDEST LAW
//
// Trade Titan can bend the execution world around the requirement.
// It cannot bend the requirement around the execution world.
// ---------------------------------------------------------------------------
namespace Laws {

inline constexpr bool tradeTitanCanChangeStoneForm()   noexcept { return true;  }
inline constexpr bool tradeTitanCanChangeStoneMeaning() noexcept { return false; }
inline constexpr bool tradeTitanCanWeakenRequirement()  noexcept { return false; }

inline constexpr bool reverseTitanCanChangeStoneForm()      noexcept { return true;  }
inline constexpr bool reverseTitanCanChangeStoneMeaning()   noexcept { return true;  }
inline constexpr bool reverseTitanCanChangeRequiredBehavior() noexcept { return false; }

inline constexpr bool physical48ReportedAsPhysical96()  noexcept { return false; }
inline constexpr bool physical48ExposedAsLogical96()    noexcept { return true;  }
inline constexpr bool passRequiresRequiredBehavior()    noexcept { return true;  }
inline constexpr bool passRequiresLiteralRepresentation() noexcept { return false; }

inline constexpr bool reverseReceiptDirectionIsPassToReality() noexcept { return true;  }
inline constexpr bool passIsSource()      noexcept { return false; }
inline constexpr bool passIsConclusion() noexcept { return true;  }
inline constexpr bool missingLinkForcesUnproven()   noexcept { return true; }
inline constexpr bool contradictedLinkForcesFail()   noexcept { return true; }
inline constexpr bool titanStopsOnDeclaration()     noexcept { return false; }
inline constexpr bool titanAcceptsFakeFit()         noexcept { return false; }

} // namespace Laws

} // namespace RawrXD::Operators

#endif // RAWRXD_OPERATORS_REVERSE_RECEIPT_TRADE_TITAN_HPP