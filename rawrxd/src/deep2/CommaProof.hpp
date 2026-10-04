#pragma once
// ============================================================================
// CommaProof.hpp — RAWRXD_COMMAPROOF_DREAMLESS_001
//
//   DREAM may propose.
//   DREAMCATCH may freeze.
//   CHASERS may execute.
//   COMMAPROOF knows none of them.
//
// COMMAPROOF only knows what happened. Each comma closes one independently
// testable fact. There is deliberately no API for adding a forecast:
//
//     PREDICTION_ALLOWED          = 0
//     ESTIMATION_ALLOWED         = 0
//     DREAM_STATE_ALLOWED        = 0
//     INFERRED_FACT              = FORBIDDEN
//     MISSING_FACT               = NA
//     UNKNOWN_FACT               = NA
//     VERDICT_DERIVED_FROM_FACTS = 1
//     VERDICT_MAY_NOT_CREATE_FACTS = 1
//
// A proof that can hold a prediction is not a proof. The type enforces this by
// construction: observe() is the only mutator, it demands a Source, and only
// Source::Observed is accepted. Everything else is rejected at the call, not by
// convention.
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace proof {

enum class Source : std::uint8_t {
    Observed = 0,   // the ONLY accepted source
    Unknown  = 1,   // explicitly not known
};

struct Fact {
    std::string key;
    std::string value;      // "NA" when unknown or missing
    Source     source = Source::Observed;
};

class CommaProof {
public:
    CommaProof() = default;

    // Record an observed fact. Rejects empty keys.
    bool observe(std::string key, std::string value);

    // Record that a fact is NOT KNOWN. This is not the same as omitting it:
    // an omitted fact is invisible, and an unknown fact is auditable.
    bool recordUnknown(std::string key);

    // ---- queries ----
    bool        has(const std::string& key) const;
    std::string get(const std::string& key) const;      // "NA" when absent
    std::uint64_t getU64(const std::string& key) const; // 0 when absent/NaN
    const Fact* find(const std::string& key) const;

    std::size_t size() const { return facts_.size(); }
    const std::vector<Fact>& facts() const { return facts_; }

    // ---- emission ----
    // Comma-separated, one atom per element. Deterministic order: insertion
    // order, because a proof read by a human should match how it was collected.
    std::string toLine() const;

    // ---- verification ----
    // A proof is valid only if EVERY fact is Observed and no value is empty.
    // Unknown is permitted and encodes as NA.
    struct Audit {
        bool valid = false;
        std::uint32_t factCount = 0;
        std::uint32_t observed = 0;
        std::uint32_t unknown = 0;
        std::uint32_t emptyValues = 0;
        std::string firstProblem;
    };
    Audit audit() const;

    // ------------------------------------------------------------------
    // ENDPOINT + REQUIREMENTS, DECLARED BEFORE EXECUTION.
    //
    // The verdict is a pure FUNCTION of (endpoint, fact set). It is never a
    // narrative, and order carries no meaning:
    //
    //     COMMA_IS_FACT_BOUNDARY  = 1
    //     COMMA_IS_SEQUENCE       = 0
    //     PROOF_ORDER_IMPLIES_CAUSALITY = 0
    //
    // Two rules make this a proof rather than a log:
    //
    //     NO_INFERRED_PASS_FROM_NEIGHBOR = 1
    //         A missing or failed requirement NEVER inherits success from an
    //         adjacent fact. shards_complete=1 says nothing about admission.
    //     FAILED_FACT_REMAINS_FAILED    = 1
    //     MISSING_FACT_REMAINS_UNKNOWN  = 1
    //         A required fact that was never observed yields UNKNOWN, which is
    //         not a pass.
    // ------------------------------------------------------------------
    struct Requirement {
        std::string key;
        std::string expected;        // exact string equality
        bool        numeric = false; // compare as numbers instead
        bool        numericGreater = false;
        std::string why;              // what this fact establishes
    };

    // Declared before execution. Re-declaring after facts exist is refused, so a
    // requirement set cannot be widened once reality is known.
    bool declareEndpoint(std::string endpoint,
                         const std::vector<Requirement>& required);

    const std::string& endpoint() const { return endpoint_; }
    const std::vector<Requirement>& requirements() const { return required_; }
    bool endpointDeclared() const { return !endpoint_.empty(); }

    enum class ReqState : std::uint8_t {
        PASS = 0,
        FAIL = 1,
        UNKNOWN = 2,
    };

    struct Verdict {
        std::string endpoint;
        std::uint32_t required = 0;
        std::uint32_t passed = 0;
        std::uint32_t failed = 0;
        std::uint32_t unknown = 0;
        bool reached = false;          // true only when passed == required
        bool indeterminate = false;    // any UNKNOWN -> cannot claim reached
        std::string firstUnsatisfied;
        std::vector<std::string> lines;
    };

    Verdict verdict() const;

    // Parse a comma line back into a proof, for replay. Returns false on a
    // malformed line. Used to check that a receipt round-trips.
    static bool parse(const std::string& line, CommaProof& out);

private:
    std::vector<Fact> facts_;
    std::string endpoint_;
    std::vector<Requirement> required_;
    bool requirementsFrozen_ = false;
    bool add(std::string key, std::string value, Source s);
};

} // namespace proof
} // namespace Deep2