#include "RuntimeManifest.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace RawrXD::Self {

const char* toString(ComponentState s) {
    switch (s) {
    case ComponentState::Active: return "ACTIVE";
    case ComponentState::PresentNotActive: return "PRESENT_NOT_ACTIVE";
    case ComponentState::Disabled: return "DISABLED";
    case ComponentState::Fallback: return "FALLBACK";
    case ComponentState::Missing: return "MISSING";
    case ComponentState::Broken: return "BROKEN";
    case ComponentState::Uncertified: return "UNCERTIFIED";
    case ComponentState::Closed: return "CLOSED";
    case ComponentState::Open: return "OPEN";
    case ComponentState::Blocked: return "BLOCKED";
    }
    return "UNKNOWN";
}

const char* toString(TodoPriority p) {
    switch (p) {
    case TodoPriority::P0: return "P0";
    case TodoPriority::P1: return "P1";
    case TodoPriority::P2: return "P2";
    }
    return "P?";
}

static std::string readFile(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static bool containsCi(const std::string& hay, const char* needle) {
    auto lower = [](char c) {
        return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
    };
    if (!needle || !*needle) return true;
    for (size_t i = 0; i < hay.size(); ++i) {
        size_t j = 0;
        while (needle[j] && i + j < hay.size() &&
               lower(hay[i + j]) == lower(needle[j]))
            ++j;
        if (!needle[j]) return true;
    }
    return false;
}

static ComponentState classifyGateText(const std::string& text) {
    if (text.empty()) return ComponentState::Missing;
    // Prefer explicit closed markers from our GATE.txt convention.
    if (containsCi(text, "FIRST_GENUINE_FAIL = NONE") ||
        containsCi(text, "FIRST_FAIL=none") ||
        containsCi(text, "FIRST_FAIL (L1 path) = none") ||
        containsCi(text, "= CLOSED") ||
        containsCi(text, "CLOSED / PASS") ||
        (containsCi(text, "FIRST_FAIL=none") && containsCi(text, "PASS"))) {
        // If GATE also says OPEN sparse tips as next, rung itself may still be closed.
        if (containsCi(text, "INVALIDATED") && containsCi(text, "not a Deep2"))
            return ComponentState::Closed;
        if (containsCi(text, "L1 FFN") && containsCi(text, "CLOSED") &&
            containsCi(text, "FIRST_FAIL (L1 path) = none"))
            return ComponentState::Closed;
        if (containsCi(text, "blk.1.attn_output") && containsCi(text, "CLOSED"))
            return ComponentState::Closed;
        if (containsCi(text, "LAYER0_OUT") && containsCi(text, "CLOSED"))
            return ComponentState::Closed;
        if (containsCi(text, "TOKENIZER") && containsCi(text, "CLOSED"))
            return ComponentState::Closed;
    }
    if (containsCi(text, "FIRST_FAIL=") && !containsCi(text, "FIRST_FAIL=none") &&
        !containsCi(text, "FIRST_FAIL (L1 path) = none")) {
        // Tip FAIL under incomplete oracle → Uncertified, not Broken.
        if (containsCi(text, "NOT a localized") ||
            containsCi(text, "oracle") && containsCi(text, "MISSING"))
            return ComponentState::Uncertified;
        return ComponentState::Broken;
    }
    if (containsCi(text, "CLOSED")) return ComponentState::Closed;
    if (containsCi(text, "PASS") && containsCi(text, "FIRST_FAIL=none"))
        return ComponentState::Closed;
    return ComponentState::Open;
}

static std::string nowIso() {
    const auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return buf;
}

RuntimeManifestSnapshot buildCertLadderManifest(const std::string& evidenceRoot) {
    RuntimeManifestSnapshot snap;
    snap.generatedAt = nowIso();
    const fs::path root(evidenceRoot);

    struct Spec {
        const char* id;
        const char* title;
        const char* gateRel; // relative GATE or dir
        const char* lockedNote; // if no file, use when sibling proves closed
    };

    // Canonical ordered ladder — DO NOT reorder without cert authority change.
    const Spec specs[] = {
        {"gate1.tokenizer", "Gate1 / tokenizer + chat template",
         "TOKENIZER_PARITY_001", "CLOSED (Gate1Freeze)"},
        {"l0.attn_ffn", "L0 attention + FFN → LAYER0_OUT",
         "BATCH2_FFN_LADDER_001/GATE.txt", nullptr},
        {"l1.attn", "L1 attention / wo (ATTN_OUT_LOC)",
         "BATCH2_L1_ATTN_OUT_LOC/GATE.txt", nullptr},
        {"l1.ffn", "L1 FFN → L1_LAYER_OUT",
         "BATCH2_L1_FFN_LADDER_001/GATE.txt", nullptr},
        {"sparse.tips", "Sparse tips L2/L4/L8/L12/L16/L21 under FORCE L0..21",
         "BATCH2_SPARSE_TIPS_001/GATE.txt", nullptr},
        {"tip.final_norm", "FINAL_NORM (clean full-stack oracle)",
         "BATCH2_SPARSE_TIPS_001/GATE.txt", nullptr},
        {"tip.logits", "LOGITS parity",
         "BATCH2_SPARSE_TIPS_001/GATE.txt", nullptr},
        {"tip.argmax", "ARGMAX / greedy tip token",
         "BATCH2_SPARSE_TIPS_001/GATE.txt", nullptr},
        {"decode.kv", "Multi-token decode + KV parity",
         "", nullptr},
        {"agent.schema_pre_dispatch", "Strict pre-dispatch tool schema",
         "AGENT_TOOL_EFFECT_001", nullptr},
        {"agent.schema_retry", "Schema rejection → correction retry",
         "AGENT_TOOL_EFFECT_001", nullptr},
        {"agent.edit_e2e", "Model-driven edit → compile → repair E2E",
         "", nullptr},
        {"lifecycle.soak", "Lifecycle / soak / failure recovery",
         "", nullptr},
        {"dist.clean_machine", "Clean-machine offline distribution",
         "", nullptr},
        {"perf.competitive", "Competitive same-hardware performance cert",
         "", nullptr},
    };

    bool prefixClosed = true;
    for (const Spec& sp : specs) {
        LadderRung r;
        r.id = sp.id;
        r.title = sp.title;
        r.evidence = sp.gateRel ? sp.gateRel : "";

        fs::path gatePath = root / (sp.gateRel ? sp.gateRel : "");
        std::string text;
        if (!r.evidence.empty()) {
            if (fs::is_directory(gatePath)) {
                // Prefer GATE.txt inside dir; else any VERDICT.txt
                if (fs::exists(gatePath / "GATE.txt"))
                    text = readFile(gatePath / "GATE.txt");
                else if (fs::exists(gatePath / "VERDICT.txt"))
                    text = readFile(gatePath / "VERDICT.txt");
                else
                    r.state = ComponentState::Missing;
            } else if (fs::exists(gatePath)) {
                text = readFile(gatePath);
            } else {
                // Try sibling dirs that imply closed for early rungs
                if (std::string(sp.id) == "gate1.tokenizer") {
                    r.state = ComponentState::Closed;
                    r.note = sp.lockedNote ? sp.lockedNote : "frozen";
                } else if (std::string(sp.id) == "sparse.tips" ||
                           std::string(sp.id).rfind("tip.", 0) == 0) {
                    // Fall back: SPARSE_CLEAN dumps exist ⇒ oracle ready, tip score open
                    if (fs::exists(root / "BATCH2_SPARSE_CLEAN_001" / "llama" /
                                   "llama_LAYER21_OUT_pos0_layer0_full_n2048_seq019.bin")) {
                        r.state = ComponentState::Open;
                        r.note = "oracle dumps ready (SPARSE_CLEAN APPLIED=22); GATE not written yet";
                        r.evidence = "BATCH2_SPARSE_CLEAN_001";
                    } else {
                        r.state = ComponentState::Blocked;
                        r.note = "need REF_CB_MAX_LAYER>=21 + FORCE_EXPAND_V 0..21";
                    }
                } else {
                    r.state = ComponentState::Missing;
                    r.note = "no GATE.txt";
                }
            }
        } else {
            r.state = prefixClosed ? ComponentState::Open : ComponentState::Blocked;
            r.note = "no evidence path yet";
        }

        if (!text.empty()) {
            r.state = classifyGateText(text);
            // Specialize sparse/tip rungs from L1_FFN GATE (says sparse OPEN)
            if (std::string(sp.id) == "sparse.tips" ||
                std::string(sp.id).rfind("tip.", 0) == 0) {
                if (containsCi(text, "SPARSE TIPS") && containsCi(text, "OPEN")) {
                    r.state = ComponentState::Open;
                    r.note = "L1 closed; sparse not scored under full FORCE yet";
                }
                if (containsCi(text, "FIRST_FAIL=FINAL_NORM") &&
                    containsCi(text, "NOT a localized")) {
                    r.state = ComponentState::Uncertified;
                    r.note = "prior FINAL_NORM fail under incomplete FORCE — re-score on SPARSE_CLEAN";
                }
            }
            if (std::string(sp.id) == "l1.ffn" && containsCi(text, "L1 FFN") &&
                containsCi(text, "CLOSED")) {
                r.state = ComponentState::Closed;
                r.note = "FIRST_FAIL (L1 path)=none";
            }
            if (std::string(sp.id) == "l1.attn" && containsCi(text, "CLOSED") &&
                containsCi(text, "INVALIDATED")) {
                r.state = ComponentState::Closed;
            }
            if (std::string(sp.id) == "l0.attn_ffn" &&
                (containsCi(text, "LAYER0_OUT") || containsCi(text, "LAYER0")) &&
                containsCi(text, "CLOSED")) {
                r.state = ComponentState::Closed;
            }
        }

        // Gate1: also closed if Gate1Freeze exists in tree (compile-time); evidence optional
        if (std::string(sp.id) == "gate1.tokenizer" &&
            r.state == ComponentState::Missing) {
            r.state = ComponentState::Closed;
            r.note = "Gate1Freeze TOKENIZER_CERTIFIED";
        }

        if (!prefixClosed && r.state == ComponentState::Open)
            r.state = ComponentState::Blocked;

        if (r.state != ComponentState::Closed)
            prefixClosed = false;

        snap.ladder.push_back(std::move(r));
    }

    // Ordered next todos: first non-closed rungs + product gates
    int ord = 1;
    for (const auto& r : snap.ladder) {
        if (r.state == ComponentState::Closed) continue;
        OrderedTodo t;
        t.ordinal = ord++;
        t.id = r.id;
        t.title = r.title;
        t.evidenceHint = r.evidence;
        t.reason = r.note.empty() ? toString(r.state) : r.note;
        if (r.state == ComponentState::Blocked) {
            t.priority = TodoPriority::P1;
            t.reason = "blocked by earlier open rung";
        } else if (r.state == ComponentState::Broken) {
            t.priority = TodoPriority::P0;
            t.reason = "FIRST_FAIL under clean oracle — localize before advancing";
        } else if (r.id.rfind("agent.", 0) == 0 || r.id.rfind("tip.", 0) == 0 ||
                   r.id == "sparse.tips") {
            t.priority = TodoPriority::P0;
        } else {
            t.priority = TodoPriority::P1;
        }
        // Collect blockers = prior open/broken ids
        for (const auto& prev : snap.ladder) {
            if (prev.id == r.id) break;
            if (prev.state != ComponentState::Closed)
                t.blockedBy.push_back(prev.id);
        }
        snap.nextTodos.push_back(std::move(t));
        if (snap.firstOpen.empty()) snap.firstOpen = r.id;
    }

    snap.firstGenuineFail = "NONE";
    for (const auto& r : snap.ladder) {
        if (r.state == ComponentState::Broken) {
            snap.firstGenuineFail = r.id;
            break;
        }
        if (r.id == "l1.ffn" && r.state == ComponentState::Closed)
            snap.firstGenuineFail = "NONE through L1_LAYER_OUT";
    }

    return snap;
}

static std::string esc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"' || c == '\\') o.push_back('\\');
        if (c == '\n') {
            o += "\\n";
            continue;
        }
        o.push_back(c);
    }
    return o;
}

std::string snapshotToJson(const RuntimeManifestSnapshot& s) {
    std::ostringstream o;
    o << "{\n";
    o << "  \"generatedAt\": \"" << esc(s.generatedAt) << "\",\n";
    o << "  \"authorityRule\": \"" << esc(s.authorityRule) << "\",\n";
    o << "  \"firstOpen\": \"" << esc(s.firstOpen) << "\",\n";
    o << "  \"firstGenuineFail\": \"" << esc(s.firstGenuineFail) << "\",\n";
    o << "  \"ladder\": [\n";
    for (size_t i = 0; i < s.ladder.size(); ++i) {
        const auto& r = s.ladder[i];
        o << "    {\"id\":\"" << esc(r.id) << "\",\"title\":\"" << esc(r.title)
          << "\",\"state\":\"" << toString(r.state) << "\",\"evidence\":\""
          << esc(r.evidence) << "\",\"note\":\"" << esc(r.note) << "\"}";
        o << (i + 1 < s.ladder.size() ? ",\n" : "\n");
    }
    o << "  ],\n";
    o << "  \"nextTodos\": [\n";
    for (size_t i = 0; i < s.nextTodos.size(); ++i) {
        const auto& t = s.nextTodos[i];
        o << "    {\"ordinal\":" << t.ordinal << ",\"priority\":\"" << toString(t.priority)
          << "\",\"id\":\"" << esc(t.id) << "\",\"title\":\"" << esc(t.title)
          << "\",\"reason\":\"" << esc(t.reason) << "\",\"evidenceHint\":\""
          << esc(t.evidenceHint) << "\",\"blockedBy\":[";
        for (size_t j = 0; j < t.blockedBy.size(); ++j) {
            o << "\"" << esc(t.blockedBy[j]) << "\"";
            if (j + 1 < t.blockedBy.size()) o << ",";
        }
        o << "]}";
        o << (i + 1 < s.nextTodos.size() ? ",\n" : "\n");
    }
    o << "  ]\n}\n";
    return o.str();
}

std::string snapshotToTodoBoard(const RuntimeManifestSnapshot& s) {
    std::ostringstream o;
    o << "RawrXD CertLadder Manifest — WHAT'S NEXT\n";
    o << "generated: " << s.generatedAt << "\n";
    o << "rule: " << s.authorityRule << "\n";
    o << "firstGenuineFail: " << s.firstGenuineFail << "\n";
    o << "firstOpen: " << (s.firstOpen.empty() ? "(none)" : s.firstOpen) << "\n\n";

    o << "LADDER\n";
    o << "------\n";
    for (const auto& r : s.ladder) {
        o << "  [" << toString(r.state) << "] " << r.id << " — " << r.title;
        if (!r.note.empty()) o << "  (" << r.note << ")";
        o << "\n";
    }

    o << "\nNEXT TODOS (in order)\n";
    o << "--------------------\n";
    if (s.nextTodos.empty()) {
        o << "  (empty — ladder complete through registered rungs)\n";
    } else {
        for (const auto& t : s.nextTodos) {
            o << "  " << t.ordinal << ". [" << toString(t.priority) << "] " << t.id
              << "\n     " << t.title << "\n     reason: " << t.reason << "\n";
            if (!t.blockedBy.empty()) {
                o << "     blocked_by:";
                for (const auto& b : t.blockedBy) o << " " << b;
                o << "\n";
            }
            if (!t.evidenceHint.empty())
                o << "     evidence: " << t.evidenceHint << "\n";
        }
    }
    o << "\nDO_NOW = " << (s.firstOpen.empty() ? "(none)" : s.firstOpen) << "\n";
    return o.str();
}

} // namespace RawrXD::Self
