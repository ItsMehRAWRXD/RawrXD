// ============================================================================
// AgentBridge.cpp
// ============================================================================

#include "agent/AgentBridge.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace rawrxd::agent {

namespace {

std::string trim(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Pull "key": "value"  /  key="value"  /  key=value out of a blob.
// The returned flag says whether the key was present. Values are NOT guessed:
// a missing key leaves the destination untouched.
bool extractField(const std::string& in, const std::string& key,
                  std::string& out) {
    std::string k = lower(key);

    // JSON-ish:  "key" : "value"
    {
        std::string pat = "\"" + k + "\"";
        std::size_t p = lower(in).find(pat);
        if (p != std::string::npos) {
            std::size_t i = p + pat.size();
            while (i < in.size() && (in[i] == ' ' || in[i] == ':')) ++i;
            if (i < in.size() && (in[i] == '"' || in[i] == '\'')) {
                const char q = in[i++];
                std::string v;
                while (i < in.size() && in[i] != q) v += in[i++];
                out = trim(v);
                return true;
            }
        }
    }
    // key=value  /  key: value
    for (const char* sep : {"=", ":"}) {
        std::string pat = k + sep;
        std::size_t p = lower(in).find(pat);
        if (p == std::string::npos) continue;
        // Guard against matching inside a longer word: the character before the
        // key must not be alphanumeric.
        if (p > 0) {
            const char prev = static_cast<char>(std::tolower(
                static_cast<unsigned char>(in[p - 1])));
            if (std::isalnum(static_cast<unsigned char>(prev))) continue;
        }
        std::size_t i = p + pat.size();
        if (i < in.size() && (in[i] == '"' || in[i] == '\'')) {
            const char q = in[i++];
            std::string v;
            while (i < in.size() && in[i] != q) v += in[i++];
            out = trim(v);
            return true;
        }
        std::size_t e = i;
        while (e < in.size() && in[e] != ',' && in[e] != '}' && in[e] != '>'
               && in[e] != '\n' && in[e] != '"' && in[e] != ' ')
            ++e;
        out = trim(in.substr(i, e - i));
        return true;
    }
    return false;
}

// Extracts the text between the first pair of delimiters, if present.
bool extractBlock(const std::string& in, const std::string& open,
                  const std::string& close, std::string& out) {
    const std::size_t a = lower(in).find(lower(open));
    if (a == std::string::npos) return false;
    const std::size_t b = lower(in).find(lower(close), a + open.size());
    if (b == std::string::npos) return false;
    out = trim(in.substr(a + open.size(), b - a - open.size()));
    return true;
}

// A surface URI is only recognized when the model actually wrote one. The
// adapter does not substitute a default, because a default surface would let a
// model that named nothing still reach an authority.
bool normalizeSurface(std::string s, std::string& out) {
    s = trim(s);
    const std::string l = lower(s);
    if (l.rfind("app://", 0) == 0 || l.rfind("browser", 0) == 0)
        { out = "app://browser"; return true; }
    if (l.rfind("files", 0) == 0 || l.rfind("file", 0) == 0)
        { out = "app://files"; return true; }
    if (l.rfind("terminal", 0) == 0)
        { out = "app://terminal"; return true; }
    if (l.rfind("ide", 0) == 0)
        { out = "app://ide"; return true; }
    return false;
}

bool normalizeOperation(std::string s, std::string& out) {
    s = trim(s);
    const std::string u = lower(s);
    for (const char* op : {"CLICK", "TYPE", "NAVIGATE", "EXISTS", "SIZE", "READ"}) {
        if (u == op) { out = op; return true; }
    }
    if (u.rfind("click", 0) == 0)     { out = "CLICK";     return true; }
    if (u.rfind("type", 0) == 0)      { out = "TYPE";      return true; }
    if (u.rfind("navigate", 0) == 0 ||
        u.rfind("open", 0) == 0 ||
        u.rfind("goto", 0) == 0)      { out = "NAVIGATE";  return true; }
    if (u.rfind("exists", 0) == 0)    { out = "EXISTS";    return true; }
    if (u.rfind("size", 0) == 0)      { out = "SIZE";      return true; }
    if (u.rfind("read", 0) == 0)      { out = "READ";      return true; }
    return false;
}

bool commonParse(const std::string& raw, ToolIntent& out) {
    std::string surface, operation, target, payload, seq;
    const bool gotSurface = extractField(raw, "surface", surface) ||
                            extractField(raw, "app", surface);
    const bool gotOp      = extractField(raw, "operation", operation) ||
                            extractField(raw, "op", operation) ||
                            extractField(raw, "action", operation);
    const bool gotTarget  = extractField(raw, "target", target) ||
                            extractField(raw, "selector", target) ||
                            extractField(raw, "path", target);

    // An intent with no surface, no operation or no target is not an intent.
    // All three must be present AND recognized.
    if (!gotSurface || !gotOp || !gotTarget) return false;
    if (!normalizeSurface(surface, out.surface)) return false;
    if (!normalizeOperation(operation, out.operation)) return false;
    if (target.empty()) return false;
    out.target = target;

    extractField(raw, "payload", payload);
    out.payload = payload;
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
bool NativeToolIntentAdapter::parse(const std::string& raw, ToolIntent& out) {
    out.source = ToolIntentSource::NativeToolCall;
    out.kind   = ToolIntentKind::Shell;
    if (!commonParse(raw, out)) return false;
    // A native call is by definition already normalized, so no hotpatch step.
    return true;
}

bool PuppeteerToolIntentAdapter::parse(const std::string& raw, ToolIntent& out) {
    out.source = ToolIntentSource::Puppeteered;
    out.kind   = ToolIntentKind::Shell;

    // Try the delimited forms first, then the whole text. A delimited block is
    // stronger evidence of intent than loose key=value pairs in prose.
    static const char* kOpens[]  = {"<tool>", "<rawrxd-tool>", "\"tool\"",
                                    "```tool", "TOOL:"};
    static const char* kCloses[] = {"</tool>", "</rawrxd-tool>", "\"",
                                    "```", "\n"};
    for (std::size_t i = 0; i < sizeof(kOpens) / sizeof(kOpens[0]); ++i) {
        std::string body;
        if (extractBlock(raw, kOpens[i], kCloses[i], body) && !body.empty()) {
            if (commonParse(body, out)) return true;
        }
    }
    return commonParse(raw, out);
}

bool PuppeteerToolIntentAdapter::claimsPass(const std::string& raw) {
    const std::string l = lower(raw);
    return l.find("verdict=pass") != std::string::npos
        || l.find("\"verdict\":\"pass\"") != std::string::npos
        || l.find("status=pass") != std::string::npos
        || l.find("success=true") != std::string::npos;
}

std::string PuppeteerToolIntentAdapter::renderObservation(
        const AgentObservation& obs) {
    // Only measured values. The model's own claim is deliberately NOT echoed:
    // returning it would let the model read back its own assertion as though
    // it were a result.
    std::ostringstream o;
    o << "<tool_result>\n";
    o << "surface="   << obs.surface   << "\n";
    o << "operation=" << obs.operation << "\n";
    o << "target="    << obs.target    << "\n";
    o << "intent_produced=" << (obs.intentProduced ? 1 : 0) << "\n";
    o << "action_executed=" << (obs.actionExecuted ? 1 : 0) << "\n";
    o << "evidence_present=" << (obs.evidencePresent ? 1 : 0) << "\n";
    o << "verdict=" << agentVerdictName(obs.verdict) << "\n";
    o << "result="  << obs.result << "\n";
    o << "detail="  << obs.detail << "\n";
    o << "</tool_result>";
    return o.str();
}

// ---------------------------------------------------------------------------
AgentDispatchResult AgentBridge::dispatch(const ToolIntent& intent) {
    using namespace rawrxd::shell;

    AgentDispatchResult out;
    out.intent = intent;

    AgentObservation& obs = out.observation;
    obs.sequence = intent.sequence;
    obs.surface  = intent.surface;
    obs.operation = intent.operation;
    obs.target   = intent.target;

    // Not a shell intent: nothing to do, and the observation says so rather
    // than reporting an empty success.
    if (intent.kind != ToolIntentKind::Shell) {
        obs.detail = std::string("intent kind is ") + toolIntentKindName(intent.kind)
                   + ", not SHELL";
        obs.verdict = AgentVerdict::Unproven;
        return out;
    }

    // ---- NORMALIZE: the whole of the bridge's contribution ----------------
    ShellAction action;
    action.operation  = intent.operation;
    action.target     = intent.target;
    action.payload    = intent.payload;
    action.sequence   = intent.sequence;

    ShellSurfaceId id;
    if (!shell_.surfaceIdForUri(intent.surface, id)) {
        obs.detail = "no surface registered for uri " + intent.surface;
        obs.verdict = AgentVerdict::Fail;
        return out;
    }
    action.surface = id;

    // ---- DELEGATE: everything else belongs to the authority ---------------
    const std::uint64_t seq = shell_.dispatch(action);
    out.shellSequence = seq;
    if (seq == 0) {
        obs.detail = "shell authority refused the action";
        obs.verdict = AgentVerdict::Fail;
        return out;
    }
    obs.actionExecuted = true;
    obs.evidencePresent = true;

    // Copy the authority's verdict. The bridge does not compute one.
    const ShellActionEvidence* e = nullptr;
    for (const auto& rec : shell_.log())
        if (rec.sequence == seq) e = &rec;

    if (e) {
        obs.result = e->after;
        obs.detail = e->detail;
        const ShellVerdict v = deriveShellVerdict(*e);
        obs.verdict = (v == ShellVerdict::Pass)     ? AgentVerdict::Pass
                    : (v == ShellVerdict::Fail)     ? AgentVerdict::Fail
                                                   : AgentVerdict::Unproven;
        out.surfaceDetail = e->surfaceUri;
    } else {
        obs.detail = "shell produced no evidence for this sequence";
        obs.verdict = AgentVerdict::Unproven;
    }
    return out;
}

AgentDispatchResult AgentBridge::dispatchRaw(const std::string& rawModelText,
                                             ToolIntentSource source) {
    AgentDispatchResult out;

    ToolIntent intent;
    bool produced = false;
    if (source == ToolIntentSource::NativeToolCall) {
        produced = NativeToolIntentAdapter::parse(rawModelText, intent);
    } else {
        produced = PuppeteerToolIntentAdapter::parse(rawModelText, intent);
    }
    intent.source = source;
    intent.sequence = 1;

    out.observation.agentClaimedText = rawModelText.size() > 240
        ? rawModelText.substr(0, 240) + "..."
        : rawModelText;
    out.observation.agentClaimedPass =
        PuppeteerToolIntentAdapter::claimsPass(rawModelText);

    if (!produced) {
        // No intent is a legitimate, reportable outcome for a small model. It is
        // NOT converted into a default action.
        out.observation.intentProduced = false;
        out.observation.verdict = AgentVerdict::Unproven;
        out.observation.detail  = "no executable intent recognized in model output";
        out.intent = intent;
        return out;
    }

    AgentDispatchResult res = dispatch(intent);
    // Carry the PARSING facts forward. dispatch() returns a freshly constructed
    // result whose observation knows nothing about how the intent was obtained,
    // so setting these before the call silently discarded them -- the receipt
    // then showed a populated surface/operation/target alongside
    // INTENT_PRODUCED=0, which is a receipt contradicting itself.
    res.observation.intentProduced  = true;
    res.observation.agentClaimedPass = out.observation.agentClaimedPass;
    res.observation.agentClaimedText = out.observation.agentClaimedText;
    return res;
}

} // namespace rawrxd::agent