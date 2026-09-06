// ============================================================================
// hexmag_oracle_binder.cpp — Oracle/Deep2 candidate binder (no FINAL authority)
// ============================================================================
#include "core/hexmag_oracle_binder.hpp"
#include "agentic/HexMagAction.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <sstream>

namespace RawrXD {
namespace HexMag {
namespace {

std::mutex g_hookMu;
std::vector<CandidateGenerator*> g_generators;
CandidateVerifierFn g_verifier;

uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

std::string toLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool containsCi(const std::string& hay, const char* needle) {
    return toLower(hay).find(toLower(needle)) != std::string::npos;
}

bool hasActionableToken(const std::string& goal) {
    static const char* kActs[] = {
        "create", "implement", "write", "build", "fix", "repair", "make",
        "open", "run", "print", "hello", "masm", "verify", "refactor",
        "program", "code",
    };
    for (const char* a : kActs) {
        if (containsCi(goal, a)) return true;
    }
    return false;
}

bool hasDeficitMarker(const std::string& goal) {
    static const char* kMarks[] = {
        "unspecified", "need_operator", "tbd", "???", "missing information",
    };
    for (const char* m : kMarks) {
        if (containsCi(goal, m)) return true;
    }
    return false;
}

/// Usable target / evidence / path — distinguishes "Fix it." from "Fix the compile error."
bool hasUsableTargetOrEvidence(const std::string& low) {
    static const char* kTargets[] = {
        ".cpp", ".hpp", ".hxx", ".cc", ".cxx", ".h", ".c", ".md", ".asm",
        ".py", ".js", ".ts", ".json", ".txt",
        "error", "fail", "test", "line", "src/", "src\\", "file", "project",
        "compile", "function", "readme", "bug", "crash", "tokenizer",
        "main.cpp", "hello.cpp", "/", "\\",
    };
    for (const char* t : kTargets) {
        if (low.find(t) != std::string::npos) return true;
    }
    return false;
}

bool hasRepairClassVerb(const std::string& low) {
    return low.find("fix") != std::string::npos
        || low.find("repair") != std::string::npos
        || low.find("make") != std::string::npos;
}

bool hasUnresolvedPronounObject(const std::string& low) {
    // Space-prefixed pronouns catch "fix it" / "repair this" / "make them".
    return low.find(" it") != std::string::npos
        || low.find(" this") != std::string::npos
        || low.find(" that") != std::string::npos
        || low.find(" them") != std::string::npos
        || low.find("it work") != std::string::npos;
}

/// action verb + unresolved pronoun/missing object + no usable target/evidence
bool isObjectlessImperative(const std::string& goal) {
    const std::string low = toLower(goal);
    if (!hasRepairClassVerb(low)) return false;
    if (hasUsableTargetOrEvidence(low)) return false;
    if (hasUnresolvedPronounObject(low)) return true;
    // Bare repair verbs with no object at all ("Fix." / "Repair")
    std::string stripped;
    for (unsigned char c : low) {
        if (std::isalnum(c) || c == ' ') stripped.push_back(static_cast<char>(c));
    }
    while (!stripped.empty() && stripped.front() == ' ') stripped.erase(stripped.begin());
    while (!stripped.empty() && stripped.back() == ' ') stripped.pop_back();
    return stripped == "fix" || stripped == "repair" || stripped == "make"
        || stripped == "make work";
}

/// Strip authority-looking FINAL phrases; body remains candidate text only.
std::string stripFinalWording(std::string t, bool* had) {
    static const char* kPhrases[] = {
        "llm.answer.final",
        "answer.final",
        "goal.satisfied",
        "FINAL:",
        "final answer:",
        "#FINAL",
    };
    std::string low = toLower(t);
    for (const char* p : kPhrases) {
        std::string pl = toLower(p);
        for (;;) {
            auto pos = low.find(pl);
            if (pos == std::string::npos) break;
            *had = true;
            t.erase(pos, pl.size());
            low.erase(pos, pl.size());
        }
    }
    // Trim whitespace
    while (!t.empty() && (t.front() == ' ' || t.front() == '\n' || t.front() == '\r'
                          || t.front() == '\t' || t.front() == ':' || t.front() == '-')) {
        t.erase(t.begin());
    }
    while (!t.empty() && (t.back() == ' ' || t.back() == '\n' || t.back() == '\r'
                          || t.back() == '\t')) {
        t.pop_back();
    }
    return t;
}

bool looksMalformed(const std::string& t) {
    if (t.size() < 8) return true;
    // Mostly non-printable / control (except newline/tab)
    size_t bad = 0;
    for (unsigned char c : t) {
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') ++bad;
        if (c == 0xFF) ++bad;
    }
    if (bad * 4 > t.size()) return true;
    // Unbalanced claim-only stubs with no substance
    if (t.find('\0') != std::string::npos) return true;
    return false;
}

bool looksUnsupportedClaimOnly(const std::string& t) {
    // After strip, if text asserts verification/authority without body
    const std::string low = toLower(t);
    if (low.find("verified without evidence") != std::string::npos) return true;
    if (low.find("claim_verified=true") != std::string::npos) return true;
    if (low.find("unsupported_claim_emission=allow") != std::string::npos) return true;
    // Pure confidence-as-fact
    if (low.find("confidence=") != std::string::npos
        && low.find("evidence") == std::string::npos
        && t.size() < 64) {
        return true;
    }
    return false;
}

} // namespace

bool goalLooksUnderspecified(const std::string& goal) {
    if (goal.empty()) return true;
    if (hasDeficitMarker(goal)) return true;
    // Imperative without resolvable object ("Fix it.") — not short-length alone.
    if (isObjectlessImperative(goal)) return true;
    if (!hasActionableToken(goal)) return true;
    return false;
}

CandidateArtifact sanitizeCandidate(std::string raw, CandidateSource src) {
    CandidateArtifact a;
    a.source = src;
    if (raw.empty()) {
        a.status = CandidateStatus::Empty;
        return a;
    }
    bool hadFinal = false;
    a.text = stripFinalWording(std::move(raw), &hadFinal);
    a.hadFinalWording = hadFinal;
    if (a.text.empty()) {
        a.status = CandidateStatus::Empty;
        return a;
    }
    if (looksMalformed(a.text)) {
        a.status = CandidateStatus::Malformed;
        return a;
    }
    if (looksUnsupportedClaimOnly(a.text)) {
        a.status = CandidateStatus::UnsupportedClaim;
        return a;
    }
    a.status = CandidateStatus::Ok;
    return a;
}

CandidateArtifact selectDeterministic(const std::vector<CandidateArtifact>& cands,
                                      std::string* evidenceOut) {
    CandidateArtifact best;
    best.status = CandidateStatus::Empty;
    uint64_t bestHash = ~0ull;
    int okCount = 0;
    for (const auto& c : cands) {
        if (c.status != CandidateStatus::Ok) continue;
        ++okCount;
        const uint64_t h = fnv1a64(c.text);
        if (best.status != CandidateStatus::Ok || h < bestHash
            || (h == bestHash && c.text < best.text)) {
            best = c;
            bestHash = h;
        }
    }
    if (evidenceOut) {
        std::ostringstream oss;
        oss << "selection=fnv1a_min ok_count=" << okCount
            << " selected_hash=" << bestHash
            << " source=" << candidateSourceName(best.source);
        *evidenceOut = oss.str();
    }
    return best;
}

BinderResult runOracleBinder(const BinderRequest& req,
                             const std::vector<CandidateGenerator*>& generators,
                             CandidateVerifierFn verifier) {
    BinderResult out;

    if (req.needInputLatched || goalLooksUnderspecified(req.prompt)) {
        out.error = "NEED_INPUT: oracle/codegen not invoked";
        out.detail = "needInput_latch_or_underspec";
        out.selected.status = CandidateStatus::SkippedNeedInput;
        out.claim.state = ClaimState::MissingInput;
        out.claim.text = "INSUFFICIENT_INFORMATION";
        // Invariant: cannot resurrect FINAL
        out.gateAllowFinal = false;
        out.gateIsAllowedFinalClaim = false;
        out.success = false;
        return out;
    }

    const std::string roleCtx =
        std::string("hexmag.candidate_only role=codegen context=") + req.context.substr(0, 400);

    for (CandidateGenerator* g : generators) {
        if (!g || !g->available()) continue;
        out.codegenInvoked = true;
        if (g->source() == CandidateSource::Oracle) out.oracleInvoked = true;
        if (g->source() == CandidateSource::Deep2) out.deep2Invoked = true;
        if (g->source() == CandidateSource::Scripted) out.oracleInvoked = true; // cert stand-in
        if (g->source() == CandidateSource::W0) out.oracleInvoked = true; // weightless solver swarm

        std::string raw;
        try {
            raw = g->generate(req.prompt, roleCtx);
        } catch (...) {
            CandidateArtifact fail;
            fail.source = g->source();
            fail.status = CandidateStatus::OracleFailure;
            out.candidates.push_back(fail);
            continue;
        }
        if (raw.empty()) {
            CandidateArtifact fail;
            fail.source = g->source();
            fail.status = CandidateStatus::OracleFailure;
            out.candidates.push_back(std::move(fail));
            continue;
        }
        out.candidates.push_back(sanitizeCandidate(std::move(raw), g->source()));
        if (out.candidates.size() >= req.maxCandidates) break;
    }

    if (!out.codegenInvoked) {
        out.error = "no candidate generator available";
        out.selected.status = CandidateStatus::OracleFailure;
        out.claim.state = ClaimState::Candidate;
        return out;
    }

    out.selected = selectDeterministic(out.candidates, &out.selectionEvidence);

    if (out.selected.status == CandidateStatus::OracleFailure
        || (out.candidates.size() == 1
            && out.candidates[0].status == CandidateStatus::OracleFailure
            && out.selected.status != CandidateStatus::Ok)) {
        // Prefer explicit failure if nothing Ok
        bool anyOk = false;
        for (const auto& c : out.candidates) {
            if (c.status == CandidateStatus::Ok) { anyOk = true; break; }
        }
        if (!anyOk) {
            out.error = "oracle_failure";
            out.claim.text = {};
            out.claim.state = ClaimState::Candidate;
            out.gateAllowFinal = false;
            out.success = false;
            return out;
        }
    }

    if (out.selected.status == CandidateStatus::Empty) {
        out.error = "empty_candidate";
        out.claim.state = ClaimState::Candidate;
        return out;
    }
    if (out.selected.status == CandidateStatus::Malformed) {
        out.error = "malformed_candidate";
        out.claim.state = ClaimState::Candidate;
        return out;
    }
    if (out.selected.status == CandidateStatus::UnsupportedClaim) {
        out.error = "unsupported_claim_in_candidate";
        out.claim.state = ClaimState::FinalRejected;
        out.claim.text = out.selected.text;
        return out;
    }
    if (out.selected.status != CandidateStatus::Ok) {
        out.error = candidateStatusName(out.selected.status);
        out.claim.state = ClaimState::Candidate;
        return out;
    }

    // Candidate text is NEVER evidence by itself.
    out.claim.text = out.selected.text;
    out.claim.state = ClaimState::Candidate;
    out.claim.confidence = 0.0;

    // Optional independent verifier → evidence (not the candidate string).
    if (verifier && verifier(out.selected)) {
        Evidence e;
        e.kind = "oracle_binder_verifier";
        e.tool = candidateSourceName(out.selected.source);
        e.payload = out.selectionEvidence; // selection metadata, not raw model "FINAL"
        e.passesVerifier = true;
        out.claim.evidence.push_back(std::move(e));
        out.claim.state = ClaimState::Verified;
        out.detail = "verified_candidate";
    } else {
        out.detail = "valid_candidate_no_verification";
        out.error = "no_verification_evidence";
    }

    // Existing FINAL gates only — binder never self-finalizes.
    ClaimFinalizeClass fin = ClaimFinalizeClass::Unverified;
    if (out.claim.state == ClaimState::Verified || out.claim.verified())
        fin = ClaimFinalizeClass::Verified;
    else if (out.claim.state == ClaimState::Proven)
        fin = ClaimFinalizeClass::Proven;

    out.gateAllowFinal = allowFinal(out.claim);
    out.gateIsAllowedFinalClaim = isAllowedFinalClaim(fin);
    out.success = out.gateAllowFinal && out.gateIsAllowedFinalClaim;
    if (!out.success && out.error.empty()) {
        out.error = "FINAL_GATE: claim not verified (candidate_as_final=FORBIDDEN)";
    }
    return out;
}

void setOracleBinderGenerators(std::vector<CandidateGenerator*> generators) {
    std::lock_guard<std::mutex> lock(g_hookMu);
    g_generators = std::move(generators);
}

std::vector<CandidateGenerator*> oracleBinderGenerators() {
    std::lock_guard<std::mutex> lock(g_hookMu);
    return g_generators;
}

void setOracleBinderVerifier(CandidateVerifierFn verifier) {
    std::lock_guard<std::mutex> lock(g_hookMu);
    g_verifier = std::move(verifier);
}

CandidateVerifierFn oracleBinderVerifier() {
    std::lock_guard<std::mutex> lock(g_hookMu);
    return g_verifier;
}

void clearOracleBinderHooks() {
    std::lock_guard<std::mutex> lock(g_hookMu);
    g_generators.clear();
    g_verifier = nullptr;
}

} // namespace HexMag
} // namespace RawrXD
