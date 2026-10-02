// ============================================================================
// ModelToolProtocol.cpp — RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
//
// Implementation notes that matter for trust:
//
//  * Every dialect scanner is independent of every other. A scan that finds a
//    call records the SPAN it came from, and a later scan is skipped when its
//    span falls inside an already-accepted one. That is what stops the
//    puppeteer from "finding" a call inside a native marker.
//  * Refusals are returned, not swallowed. An unknown tool, an ambiguous call
//    and a missing required argument each produce a rejected Intent with a
//    machine-readable error, so "the agent did nothing" is distinguishable
//    from "the agent found nothing".
//  * The probe cannot confirm a dialect RawrXD taught. See
//    ProbeNativeToolCalling.
// ============================================================================
#include "agentic/ModelToolProtocol.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

namespace rawrxd {
namespace agentic {
namespace mtproto {
namespace {

// ---------------------------------------------------------------------------
// JSON scanning. Self-contained on purpose: the authority must not depend on a
// third-party JSON library being present in whichever target links it.
// ---------------------------------------------------------------------------

bool IsWs(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

void SkipWs(const std::string& s, std::size_t& p) {
    while (p < s.size() && IsWs(s[p])) ++p;
}

bool ReadJsonStringBody(const std::string& s, std::size_t& p, std::string& out,
                        bool& badEscape) {
    badEscape = false;
    out.clear();
    if (p >= s.size() || s[p] != '"') return false;
    ++p;
    while (p < s.size()) {
        const char c = s[p];
        if (c == '"') { ++p; return true; }
        if (c == '\\') {
            if (p + 1 >= s.size()) { badEscape = true; return false; }
            const char e = s[p + 1];
            switch (e) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'u': {
                    if (p + 5 >= s.size()) { badEscape = true; return false; }
                    unsigned code = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = s[p + 2 + static_cast<std::size_t>(k)];
                        unsigned v = 0;
                        if (h >= '0' && h <= '9')      v = static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') v = static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') v = static_cast<unsigned>(h - 'A' + 10);
                        else { badEscape = true; return false; }
                        code = (code << 4) | v;
                    }
                    if (code >= 0xD800 && code <= 0xDFFF) code = 0xFFFD;
                    if (code < 0x80) {
                        out += static_cast<char>(code);
                    } else if (code < 0x800) {
                        out += static_cast<char>(0xC0 | (code >> 6));
                        out += static_cast<char>(0x80 | (code & 0x3F));
                    } else {
                        out += static_cast<char>(0xE0 | (code >> 12));
                        out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                        out += static_cast<char>(0x80 | (code & 0x3F));
                    }
                    p += 4;
                    break;
                }
                default: badEscape = true; return false;
            }
            p += 2;
            continue;
        }
        out += c;
        ++p;
    }
    return false;  // unterminated
}

// Index just past the JSON value starting at p, or npos when unterminated.
std::size_t ScanJsonValueEnd(const std::string& s, std::size_t p) {
    SkipWs(s, p);
    if (p >= s.size()) return std::string::npos;
    const char c = s[p];
    if (c == '"') {
        std::size_t q = p;
        std::string tmp;
        bool bad = false;
        if (!ReadJsonStringBody(s, q, tmp, bad)) return std::string::npos;
        return q;
    }
    if (c == '{' || c == '[') {
        std::size_t depth = 0;
        bool inStr = false;
        for (std::size_t i = p; i < s.size(); ++i) {
            const char d = s[i];
            if (inStr) {
                if (d == '\\') ++i;
                else if (d == '"') inStr = false;
                continue;
            }
            if (d == '"') { inStr = true; continue; }
            if (d == '{' || d == '[') ++depth;
            else if (d == '}' || d == ']') {
                --depth;
                if (depth == 0) return i + 1;
            }
        }
        return std::string::npos;
    }
    std::size_t i = p;
    while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ']' && !IsWs(s[i])) ++i;
    return i > p ? i : std::string::npos;
}

// Flat object reader. Container values are kept as raw JSON text so a nested
// argument still reaches the tool rather than vanishing.
bool ReadJsonObjectFlat(const std::string& s, std::size_t& p,
                        std::vector<std::pair<std::string, std::string>>& out,
                        std::string& err) {
    SkipWs(s, p);
    if (p >= s.size() || s[p] != '{') { err = "expected '{'"; return false; }
    ++p;
    for (;;) {
        SkipWs(s, p);
        if (p >= s.size()) { err = "unterminated object"; return false; }
        if (s[p] == '}') { ++p; return true; }
        std::string key;
        bool bad = false;
        if (!ReadJsonStringBody(s, p, key, bad)) {
            err = bad ? "bad escape in object key" : "unterminated object key";
            return false;
        }
        SkipWs(s, p);
        if (p >= s.size() || s[p] != ':') { err = "expected ':' after key"; return false; }
        ++p;
        SkipWs(s, p);
        const std::size_t vStart = p;
        const std::size_t vEnd = ScanJsonValueEnd(s, p);
        if (vEnd == std::string::npos) { err = "unterminated value"; return false; }
        std::string value;
        if (s[vStart] == '"') {
            std::size_t vp = vStart;
            if (!ReadJsonStringBody(s, vp, value, bad)) {
                err = "unterminated value";
                return false;
            }
        } else {
            value = s.substr(vStart, vEnd - vStart);
        }
        out.emplace_back(key, value);
        p = vEnd;
        SkipWs(s, p);
        if (p < s.size() && s[p] == ',') { ++p; continue; }
        if (p < s.size() && s[p] == '}') { ++p; return true; }
        err = p >= s.size() ? "unterminated object" : "expected ',' or '}'";
        return false;
    }
}

// Index just past the bracket group opened at `open`, or npos.
std::size_t MatchContainer(const std::string& s, std::size_t open, char o, char c) {
    if (open >= s.size() || s[open] != o) return std::string::npos;
    int depth = 0;
    bool inStr = false;
    char quote = 0;
    for (std::size_t i = open; i < s.size(); ++i) {
        const char d = s[i];
        if (inStr) {
            if (d == '\\') { ++i; continue; }
            if (d == quote) inStr = false;
            continue;
        }
        if (d == '"' || d == '\'') { inStr = true; quote = d; continue; }
        if (d == o) ++depth;
        else if (d == c) {
            --depth;
            if (depth == 0) return i + 1;
        }
    }
    return std::string::npos;
}

using KvList = std::vector<std::pair<std::string, std::string>>;

bool FindField(const KvList& kv, const char* key, std::string& out) {
    for (const auto& e : kv) {
        if (e.first == key) { out = e.second; return true; }
    }
    return false;
}

std::string Trim(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && IsWs(s[a])) ++a;
    while (b > a && IsWs(s[b - 1])) --b;
    return s.substr(a, b - a);
}

std::string Lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool WordChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

// A call shape the authority will consider: name immediately followed by '(' or
// '{'. Anything else is prose and is left alone.
struct RawCall {
    std::string name;
    KvList args;
    std::size_t begin = 0;
    std::size_t end = 0;
    std::string raw;
    std::string error;  // parse error found inside the marker
    std::vector<std::string> warnings;
};

// Reads {"name":..,"arguments":..} and its relatives into a RawCall.
void FillFromObject(const std::string& s, std::size_t begin, RawCall& rc,
                    bool allowFunctionWrapper) {
    std::size_t p = begin;
    KvList kv;
    std::string err;
    if (!ReadJsonObjectFlat(s, p, kv, err)) { rc.error = err; return; }

    if (allowFunctionWrapper) {
        std::string fn;
        if (FindField(kv, "function", fn) && !fn.empty() && fn.front() == '{') {
            std::size_t q = 0;
            KvList inner;
            std::string e2;
            if (ReadJsonObjectFlat(fn, q, inner, e2) && !inner.empty()) kv = inner;
        }
    }

    std::string name;
    if (FindField(kv, "name", name) || FindField(kv, "tool_name", name) ||
        FindField(kv, "function_name", name) || FindField(kv, "tool", name)) {
        rc.name = Trim(name);
    }
    // Accept both the object and the stringified-object forms of "arguments".
    for (const char* k : {"arguments", "parameters", "args", "input", "tool_input"}) {
        std::string blob;
        if (!FindField(kv, k, blob) || blob.empty()) continue;
        std::size_t q = 0;
        KvList inner;
        std::string e2;
        if (ReadJsonObjectFlat(blob, q, inner, e2)) {
            for (const auto& e : inner) rc.args.push_back(e);
        } else if (blob.front() == '{') {
            rc.error = "arguments is not a readable object";
        } else {
            // arguments arrived as a string: it is already unescaped by
            // ReadJsonObjectFlat, so pass it through under its own key.
            rc.args.emplace_back(std::string(k), blob);
        }
        break;
    }

    // The BARE form: the object IS the argument set. Rawr's own block
    // ({"path":"a.cpp"}), ReAct's Action Input, and a puppeteered
    // name{...} all carry no "arguments" wrapper, and reading them with only
    // the wrapped rule produces a call with a name and no arguments -- which
    // then fails validation as a missing required parameter and looks like a
    // model error rather than a parser error.
    //
    // The name is extracted first, so the bare form can never contribute a
    // "name" argument, and neither can the type/id bookkeeping fields.
    if (rc.args.empty() && rc.error.empty()) {
        static const char* kMeta[] = {"name",      "type",         "id",
                                      "function",  "tool_name",    "function_name",
                                      "tool",      "index",        "call_id"};
        for (const auto& e : kv) {
            bool meta = false;
            for (const char* m : kMeta) {
                if (e.first == m) { meta = true; break; }
            }
            if (meta) continue;
            rc.args.push_back(e);
        }
    }
}

// --- OpenAI: {"tool_calls":[{"function":{"name":..,"arguments":".."}}]} ---
std::vector<RawCall> ScanOpenAi(const std::string& s) {
    std::vector<RawCall> out;
    const std::string key = "\"tool_calls\"";
    std::size_t p = 0;
    while ((p = s.find(key, p)) != std::string::npos) {
        std::size_t v = p + key.size();
        SkipWs(s, v);
        if (v >= s.size() || s[v] != ':') { p += key.size(); continue; }
        ++v;
        SkipWs(s, v);
        if (v >= s.size() || s[v] != '[') { p += key.size(); continue; }
        const std::size_t arrEnd = MatchContainer(s, v, '[', ']');
        if (arrEnd == std::string::npos) break;
        std::size_t i = v + 1;
        while (i + 1 < arrEnd) {
            SkipWs(s, i);
            if (i + 1 >= arrEnd) break;
            if (s[i] != '{') { ++i; continue; }
            const std::size_t objEnd = MatchContainer(s, i, '{', '}');
            if (objEnd == std::string::npos || objEnd > arrEnd) break;
            RawCall rc;
            rc.begin = i;
            rc.end = objEnd;
            rc.raw = s.substr(i, objEnd - i);
            FillFromObject(s, i, rc, true);
            out.push_back(rc);
            i = objEnd;
        }
        p = arrEnd;
    }
    return out;
}

// --- Tagged blocks: hermes, qwen/glm, llama3, mistral ----------------------
//
// `lenient` covers the case where a model emits a complete tool call and is cut
// off before the closing marker, or uses a dialect whose closing marker is not
// fixed (llama-3.1 emits <|python_tag|>{...} and then <|eom_id|>). A complete,
// parseable object is accepted on its own evidence; an incomplete one is a
// refusal, because half a tool call is not a tool call.
std::vector<RawCall> ScanTagged(const std::string& s, const std::string& open,
                                const std::string& close, bool lenient = false) {
    std::vector<RawCall> out;
    if (open.empty()) return out;
    std::size_t p = 0;
    while ((p = s.find(open, p)) != std::string::npos) {
        const std::size_t bodyStart = p + open.size();
        const std::size_t closePos = close.empty() ? std::string::npos : s.find(close, bodyStart);

        RawCall rc;
        rc.begin = p;

        if (closePos == std::string::npos) {
            std::size_t q = bodyStart;
            SkipWs(s, q);
            if (lenient && q < s.size() && s[q] == '{') {
                const std::size_t objEnd = ScanJsonValueEnd(s, q);
                if (objEnd != std::string::npos) {
                    FillFromObject(s, q, rc, false);
                    if (rc.error.empty()) {
                        rc.end = objEnd;
                        rc.raw = s.substr(p, objEnd - p);
                        p = objEnd;
                        out.push_back(rc);
                        continue;
                    }
                }
            }
            rc.end = s.size();
            rc.raw = s.substr(p);
            rc.error = "unterminated_tool_block";
            out.push_back(rc);
            break;
        }
        rc.end = closePos + close.size();
        rc.raw = s.substr(p, rc.end - p);
        p = rc.end;

        std::size_t q = bodyStart;
        SkipWs(s, q);
        if (q < closePos && s[q] == '{') {
            FillFromObject(s, q, rc, false);
        } else {
            rc.error = "tool_block_body_is_not_an_object";
        }
        out.push_back(rc);
    }
    return out;
}

// --- Mistral: [TOOL_CALLS] followed by a JSON ARRAY of calls ---------------
// This one is not a tagged block: the opening token has no closing partner, and
// the payload is an array rather than a single object.
std::vector<RawCall> ScanMistral(const std::string& s) {
    std::vector<RawCall> out;
    const std::string open = "[TOOL_CALLS]";
    std::size_t p = 0;
    while ((p = s.find(open, p)) != std::string::npos) {
        const std::size_t bodyStart = p + open.size();
        std::size_t q = bodyStart;
        SkipWs(s, q);
        RawCall bad;
        bad.begin = p;
        if (q >= s.size() || s[q] != '[') {
            bad.end = s.size();
            bad.raw = s.substr(p);
            bad.error = "tool_calls_body_is_not_an_array";
            out.push_back(bad);
            break;
        }
        const std::size_t arrEnd = MatchContainer(s, q, '[', ']');
        if (arrEnd == std::string::npos) {
            bad.end = s.size();
            bad.raw = s.substr(p);
            bad.error = "unterminated_tool_calls_array";
            out.push_back(bad);
            break;
        }
        p = arrEnd;
        std::size_t i = q + 1;
        while (i + 1 < arrEnd) {
            SkipWs(s, i);
            if (i + 1 >= arrEnd) break;
            if (s[i] != '{') { ++i; continue; }
            const std::size_t objEnd = MatchContainer(s, i, '{', '}');
            if (objEnd == std::string::npos || objEnd > arrEnd) break;
            RawCall one;
            one.begin = i;
            one.end = objEnd;
            one.raw = s.substr(i, objEnd - i);
            FillFromObject(s, i, one, false);
            out.push_back(one);
            i = objEnd;
        }
    }
    return out;
}

// --- RawrXD's own taught dialect: <<<TOOL:name|{...}>>> ---------------------
std::vector<RawCall> ScanRawrToolBlock(const std::string& s) {
    std::vector<RawCall> out;
    const std::string open = "<<<TOOL:";
    const std::string close = ">>>";
    std::size_t p = 0;
    while ((p = s.find(open, p)) != std::string::npos) {
        const std::size_t bodyStart = p + open.size();
        const std::size_t closePos = s.find(close, bodyStart);
        RawCall rc;
        rc.begin = p;
        if (closePos == std::string::npos) {
            rc.end = s.size();
            rc.raw = s.substr(p);
            rc.error = "unterminated_tool_block";
            out.push_back(rc);
            break;
        }
        rc.end = closePos + close.size();
        rc.raw = s.substr(p, rc.end - p);
        p = rc.end;

        const std::size_t bar = s.find('|', bodyStart);
        if (bar == std::string::npos || bar > closePos) {
            rc.error = "no_separator_between_name_and_arguments";
            out.push_back(rc);
            continue;
        }
        rc.name = Trim(s.substr(bodyStart, bar - bodyStart));
        std::size_t q = bar + 1;
        SkipWs(s, q);
        if (q < closePos && s[q] == '{') {
            FillFromObject(s, q, rc, false);
        } else {
            rc.error = "tool_block_arguments_are_not_an_object";
        }
        out.push_back(rc);
    }
    return out;
}

// --- ReAct: "Action: name" / "Action Input: {...}" --------------------------
std::vector<RawCall> ScanReAct(const std::string& s) {
    std::vector<RawCall> out;
    std::size_t p = 0;
    while ((p = s.find("Action:", p)) != std::string::npos) {
        const std::size_t nameStart = p + 7;
        std::size_t nameEnd = s.find('\n', nameStart);
        if (nameEnd == std::string::npos) nameEnd = s.size();
        RawCall rc;
        rc.begin = p;
        rc.name = Trim(s.substr(nameStart, nameEnd - nameStart));
        // The name may itself be a JSON object; take only its leading token.
        const std::size_t sp = rc.name.find_first_of(" \t");
        if (sp != std::string::npos) rc.name = rc.name.substr(0, sp);

        const std::size_t ai = s.find("Action Input:", nameEnd);
        if (ai == std::string::npos) {
            rc.end = nameEnd;
            rc.raw = s.substr(rc.begin, rc.end - rc.begin);
            rc.error = "no_action_input";
            out.push_back(rc);
            p = nameEnd;
            continue;
        }
        std::size_t q = ai + 13;
        SkipWs(s, q);
        if (q < s.size() && s[q] == '{') {
            FillFromObject(s, q, rc, false);
            rc.end = ScanJsonValueEnd(s, q);
            if (rc.end == std::string::npos) rc.end = s.size();
        } else {
            const std::size_t lineEnd = s.find('\n', q);
            rc.args.emplace_back("input", Trim(s.substr(q, (lineEnd == std::string::npos ? s.size() : lineEnd) - q)));
            rc.end = lineEnd == std::string::npos ? s.size() : lineEnd;
        }
        rc.raw = s.substr(rc.begin, rc.end - rc.begin);
        out.push_back(rc);
        p = rc.end > rc.begin ? rc.end : rc.begin + 1;
    }
    return out;
}

// --- The puppeteer ----------------------------------------------------------
//
// Splits an argument list on commas at depth 0 outside quotes. Returns false
// when a piece cannot be read as an argument at all, which is the refusal
// path for prose that merely looks like a call.
bool SplitArgs(const std::string& content, std::vector<std::string>& pieces) {
    int depth = 0;
    char quote = 0;
    std::string cur;
    for (std::size_t i = 0; i < content.size(); ++i) {
        const char c = content[i];
        if (quote) {
            cur += c;
            if (c == '\\' && i + 1 < content.size()) { cur += content[++i]; continue; }
            if (c == quote) quote = 0;
            continue;
        }
        if (c == '"' || c == '\'') { quote = c; cur += c; continue; }
        if (c == '(' || c == '{' || c == '[') ++depth;
        if (c == ')' || c == '}' || c == ']') --depth;
        if (c == ',' && depth == 0) { pieces.push_back(Trim(cur)); cur.clear(); continue; }
        cur += c;
    }
    if (quote) return false;
    pieces.push_back(Trim(cur));
    return true;
}

std::string Unquote(const std::string& s) {
    if (s.size() >= 2 && (s.front() == '"' || s.front() == '\'') && s.back() == s.front()) {
        const std::string inner = s.substr(1, s.size() - 2);
        std::string out;
        for (std::size_t i = 0; i < inner.size(); ++i) {
            if (inner[i] == '\\' && i + 1 < inner.size()) { out += inner[++i]; continue; }
            out += inner[i];
        }
        return out;
    }
    return s;
}

const ToolDef* FindToolDef(const std::vector<ToolDef>& tools, const std::string& name) {
    for (const auto& t : tools) {
        if (t.name == name) return &t;
    }
    return nullptr;
}

// First declared parameter, preferring a required one. Used only when the model
// wrote a bare positional argument.
std::string FirstParamName(const ToolDef& def) {
    for (const auto& p : def.params) if (p.required) return p.name;
    return def.params.empty() ? std::string() : def.params.front().name;
}

std::vector<RawCall> ScanInferred(const std::string& s, const std::vector<ToolDef>& tools) {
    std::vector<RawCall> out;

    // Pass 1: names that are actually registered.
    for (const auto& def : tools) {
        if (def.name.empty()) continue;
        std::size_t p = 0;
        while ((p = s.find(def.name, p)) != std::string::npos) {
            const std::size_t nameEnd = p + def.name.size();
            const bool leftOk = p == 0 || !WordChar(s[p - 1]);
            if (!leftOk || (nameEnd < s.size() && WordChar(s[nameEnd]))) { p = nameEnd; continue; }

            std::size_t q = nameEnd;
            SkipWs(s, q);
            RawCall rc;
            rc.begin = p;
            rc.name = def.name;

            if (q >= s.size() || (s[q] != '(' && s[q] != '{')) {
                // A registered tool name followed by whitespace and a value, with
                // no brackets. This is the form a real un-trained model actually
                // writes: on 2026-10-02, tinyllama-1.1b answered a call request
                // with exactly "read_file AGENTS.md". It is also the form that
                // used to produce total silence, which is worse than a wrong
                // call -- a refusal nobody records looks identical to a model
                // that had no intent at all.
                //
                // Scoped to lines that BEGIN with the tool name, so a prompt that
                // declares tools ("Tool: read_file") is not mistaken for a call.
                const std::size_t lineStart = s.rfind('\n', p == 0 ? 0 : p - 1);
                const bool atLineStart =
                    (lineStart == std::string::npos && p == 0) ||
                    (lineStart != std::string::npos && lineStart + 1 == p) ||
                    p == 0;
                if (atLineStart && q > nameEnd) {
                    const std::size_t lineEnd = s.find('\n', q);
                    const std::string line =
                        s.substr(q, (lineEnd == std::string::npos ? s.size() : lineEnd) - q);
                    std::vector<std::string> words;
                    {
                        std::string cur;
                        for (const char ch : line) {
                            if (IsWs(ch)) {
                                if (!cur.empty()) { words.push_back(cur); cur.clear(); }
                            } else {
                                cur += ch;
                            }
                        }
                        if (!cur.empty()) words.push_back(cur);
                    }
                    RawCall bare;
                    bare.begin = p;
                    bare.name = def.name;
                    if (words.empty()) {
                        bare.end = nameEnd;
                        bare.raw = s.substr(bare.begin, bare.end - bare.begin);
                        bare.error = "tool_line_without_arguments";
                    } else if (words.size() == 1) {
                        // Accepted only for a tool with exactly one declared
                        // parameter, because the runtime would otherwise have to
                        // invent which parameter the value belongs to.
                        if (def.params.size() != 1) {
                            bare.end = lineEnd == std::string::npos ? s.size() : lineEnd;
                            bare.raw = s.substr(bare.begin, bare.end - bare.begin);
                            bare.error = "bare_argument_form_ambiguous_for_this_tool";
                        } else {
                            bare.args.emplace_back(def.params.front().name,
                                                   Unquote(words.front()));
                            bare.warnings.push_back(
                                "bare_argument_form_accepted_by_the_runtime");
                            bare.end = lineEnd == std::string::npos ? s.size() : lineEnd;
                            bare.raw = s.substr(bare.begin, bare.end - bare.begin);
                        }
                    } else {
                        bare.end = lineEnd == std::string::npos ? s.size() : lineEnd;
                        bare.raw = s.substr(bare.begin, bare.end - bare.begin);
                        bare.error = "ambiguous_bare_arguments";
                    }
                    out.push_back(bare);
                    p = bare.end > nameEnd ? bare.end : nameEnd;
                    continue;
                }
                p = nameEnd;
                continue;
            }
            if (q < s.size() && s[q] == '{') {
                FillFromObject(s, q, rc, false);
                const std::size_t objEnd = ScanJsonValueEnd(s, q);
                rc.end = objEnd == std::string::npos ? s.size() : objEnd;
                rc.raw = s.substr(rc.begin, rc.end - rc.begin);
                out.push_back(rc);
                p = rc.end > rc.begin ? rc.end : nameEnd;
                continue;
            }

            const std::size_t argEnd = MatchContainer(s, q, '(', ')');
            if (argEnd == std::string::npos) {
                rc.end = s.size();
                rc.raw = s.substr(rc.begin);
                rc.error = "unterminated_call";
                out.push_back(rc);
                break;
            }
            rc.end = argEnd;
            rc.raw = s.substr(rc.begin, rc.end - rc.begin);
            p = rc.end;

            const std::string content = s.substr(q + 1, argEnd - q - 2);
            if (Trim(content).empty()) {
                out.push_back(rc);  // bare name(): no arguments, Validate decides
                continue;
            }
            std::vector<std::string> pieces;
            if (!SplitArgs(content, pieces)) {
                rc.error = "unterminated_quoted_argument";
                out.push_back(rc);
                continue;
            }
            bool positionalUsed = false;
            std::size_t positionalCount = 0;
            for (const auto& piece : pieces) {
                if (piece.empty()) continue;
                const std::size_t eq = piece.find('=');
                if (eq != std::string::npos) {
                    std::string k = Trim(piece.substr(0, eq));
                    const std::string v = Unquote(Trim(piece.substr(eq + 1)));
                    if (k.size() >= 2 && k.front() == '"' && k.back() == '"') {
                        k = k.substr(1, k.size() - 2);
                    }
                    if (k.empty()) { rc.error = "empty_argument_name"; break; }
                    rc.args.emplace_back(k, v);
                    continue;
                }
                // Positional. Allowed only when the tool declares a parameter to
                // put it in, and recorded as a warning because the mapping is
                // the runtime's inference, not the model's.
                const std::string pn = FirstParamName(def);
                if (pn.empty()) { rc.error = "arguments_for_a_tool_that_declares_none"; break; }
                rc.args.emplace_back(pn, Unquote(piece));
                positionalUsed = true;
                ++positionalCount;
            }
            // More bare values than the tool has parameters means the runtime
            // would have to invent the mapping. Refuse rather than guess: a
            // guessed argument is a wrong tool call that reports itself as a
            // successful one.
            if (rc.error.empty() && positionalCount > 0 && positionalCount > def.params.size()) {
                rc.error = "more_positional_arguments_than_declared_parameters";
                out.push_back(rc);
                continue;
            }
            if (positionalUsed) {
                rc.warnings.push_back("positional_argument_assigned_by_the_runtime");
            }
            out.push_back(rc);
        }
    }

    // Pass 2: a call shape naming something that is NOT registered. This exists
    // so a hallucinated tool is a measured refusal instead of silence. It only
    // fires on shapes that are unambiguously call-shaped: a quoted single
    // argument, or a key=value list.
    static const std::set<std::string> kStop = {
        "the", "and", "for", "not", "but", "you", "are", "was", "let", "see", "use",
        "get", "set", "run", "call", "note", "wait", "this", "that", "with", "from",
        "have", "will", "can", "may", "its", "his", "her", "our", "out", "one", "two"};
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (i > 0 && WordChar(s[i - 1])) continue;
        if (!(std::isalpha(static_cast<unsigned char>(s[i])) || s[i] == '_')) continue;
        std::size_t j = i;
        while (j < s.size() && WordChar(s[j])) ++j;
        if (j - i < 3 || j - i > 64) { i = j - 1; continue; }
        const std::string ident = s.substr(i, j - i);
        if (kStop.count(Lower(ident))) { i = j - 1; continue; }
        if (FindToolDef(tools, ident)) { i = j - 1; continue; }

        std::size_t q = j;
        SkipWs(s, q);
        if (q >= s.size() || s[q] != '(') { i = j - 1; continue; }
        const std::size_t argEnd = MatchContainer(s, q, '(', ')');
        if (argEnd == std::string::npos) { i = j - 1; continue; }
        const std::string content = Trim(s.substr(q + 1, argEnd - q - 2));
        if (content.empty()) { i = argEnd - 1; continue; }
        const bool quoted = content.size() >= 2 &&
                            ((content.front() == '"' && content.back() == '"') ||
                             (content.front() == '\'' && content.back() == '\''));
        const bool kvList = content.find('=') != std::string::npos;
        if (!quoted && !kvList) { i = j - 1; continue; }

        RawCall rc;
        rc.begin = i;
        rc.end = argEnd;
        rc.raw = s.substr(i, argEnd - i);
        rc.name = ident;
        rc.error = "not_a_registered_tool";
        out.push_back(rc);
        i = argEnd - 1;
    }

    return out;
}

std::vector<RawCall> ScanDialect(Dialect d, const std::string& s,
                                 const std::vector<ToolDef>& tools) {
    switch (d) {
        case Dialect::OpenAiToolCalls:  return ScanOpenAi(s);
        case Dialect::HermesToolCall:   return ScanTagged(s, "<tool_call>", "</tool_call>");
        case Dialect::QwenGlmToolCall:  {
            std::vector<RawCall> out = ScanTagged(s, "<|tool_call_start|>", "<|tool_call_end|>");
            std::vector<RawCall> alt = ScanTagged(s, "<|tool_call|>", "<|tool_call_end|>");
            out.insert(out.end(), alt.begin(), alt.end());
            return out;
        }
        case Dialect::Llama3PythonTag:  return ScanTagged(s, "<|python_tag|>", "<|eom_id|>", true);
        case Dialect::MistralToolCalls: return ScanMistral(s);
        case Dialect::RawrToolBlock:  return ScanRawrToolBlock(s);
        case Dialect::LegacyReAct:    return ScanReAct(s);
        case Dialect::InferredIntent: return ScanInferred(s, tools);
        case Dialect::None:           break;
    }
    return {};
}

const ModelHotpatch* FindHotpatch(const std::vector<ModelHotpatch>& patches,
                                  const ModelIdentity& id) {
    const std::string key = Lower(id.key());
    const std::string name = Lower(id.name);
    const ModelHotpatch* best = nullptr;
    for (const auto& hp : patches) {
        const std::string hk = Lower(Trim(hp.modelKey));
        bool match = false;
        if (hk.empty() || hk == "*" || hk == "*/*") {
            match = true;
        } else {
            // "arch/family" with '*' as a per-component wildcard.
            std::vector<std::string> a, b;
            for (std::size_t p = 0;;) {
                const std::size_t s1 = key.find('/', p);
                a.push_back(s1 == std::string::npos ? key.substr(p) : key.substr(p, s1 - p));
                if (s1 == std::string::npos) break;
                p = s1 + 1;
            }
            for (std::size_t p = 0;;) {
                const std::size_t s1 = hk.find('/', p);
                b.push_back(s1 == std::string::npos ? hk.substr(p) : hk.substr(p, s1 - p));
                if (s1 == std::string::npos) break;
                p = s1 + 1;
            }
            if (a.size() == b.size()) {
                match = true;
                for (std::size_t k = 0; k < a.size(); ++k) {
                    if (b[k] != "*" && b[k] != a[k]) { match = false; break; }
                }
            }
            if (!match && !name.empty() && name.find(hk) != std::string::npos) match = true;
        }
        // A more specific key wins, so a per-model hotpatch beats a wildcard.
        if (match && (!best || hp.modelKey.size() > best->modelKey.size())) best = &hp;
    }
    return best;
}

} // namespace

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

const char* ToString(Tier v) noexcept {
    switch (v) {
        case Tier::Unsupported:     return "UNSUPPORTED";
        case Tier::Puppeteer:       return "PUPPETEER";
        case Tier::HotpatchAdapt:   return "HOTPATCH_ADAPT";
        case Tier::Native:          return "NATIVE";
    }
    return "?";
}

const char* ToString(Dialect v) noexcept {
    switch (v) {
        case Dialect::None:            return "NONE";
        case Dialect::RawrToolBlock:   return "RAWR_TOOL_BLOCK";
        case Dialect::OpenAiToolCalls: return "OPENAI_TOOL_CALLS";
        // Named for the FORMAT, not a vendor. `<tool_call>` is byte-identical
        // in Hermes 3 and Qwen2.5, and measuring a real Qwen reply labelled it
        // HERMES_TOOL_CALL -- a receipt that names the wrong family implies the
        // wrong observation convention went back to the model. Both families use
        // <tool_response> for the result, so behaviour was right and the label
        // was not.
        case Dialect::HermesToolCall:  return "XML_TOOL_CALL";
        case Dialect::QwenGlmToolCall: return "QWEN_GLM_TOOL_CALL";
        case Dialect::Llama3PythonTag: return "LLAMA3_PYTHON_TAG";
        case Dialect::MistralToolCalls:return "MISTRAL_TOOL_CALLS";
        case Dialect::LegacyReAct:     return "LEGACY_REACT";
        case Dialect::InferredIntent:  return "INFERRED_INTENT";
    }
    return "?";
}

const char* ToString(Agency v) noexcept {
    switch (v) {
        case Agency::ModelNative:    return "MODEL_NATIVE";
        case Agency::ModelUnmarked:  return "MODEL_UNMARKED";
        case Agency::RuntimeInferred:return "RUNTIME_INFERRED";
    }
    return "?";
}

const char* ToString(NativeSupport v) noexcept {
    switch (v) {
        case NativeSupport::Undeclared:  return "UNDECLARED";
        case NativeSupport::Pass:        return "PASS";
        case NativeSupport::Unsupported: return "UNSUPPORTED";
    }
    return "?";
}

bool IsTrainedProtocolDialect(Dialect d) noexcept {
    switch (d) {
        case Dialect::OpenAiToolCalls:
        case Dialect::HermesToolCall:
        case Dialect::QwenGlmToolCall:
        case Dialect::Llama3PythonTag:
        case Dialect::MistralToolCalls:
            return true;
        default:
            // RawrToolBlock and LegacyReAct are taught by RawrXD.
            // InferredIntent is produced by RawrXD.
            return false;
    }
}

std::string ModelIdentity::key() const {
    std::string a = Lower(Trim(arch));
    std::string f = Lower(Trim(chatTemplateFamily));
    if (a.empty()) a = "*";
    if (f.empty()) f = "*";
    return a + "/" + f;
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

ProtocolAuthority& ProtocolAuthority::Instance() {
    static ProtocolAuthority inst;
    return inst;
}

void ProtocolAuthority::RegisterHotpatch(const ModelHotpatch& hp) {
    for (auto& e : hotpatches_) {
        if (e.id == hp.id) { e = hp; return; }
    }
    hotpatches_.push_back(hp);
}

bool ProtocolAuthority::UnregisterHotpatch(const std::string& id) {
    for (auto it = hotpatches_.begin(); it != hotpatches_.end(); ++it) {
        if (it->id == id) { hotpatches_.erase(it); return true; }
    }
    return false;
}

void ProtocolAuthority::ClearHotpatches() { hotpatches_.clear(); }

bool ProtocolAuthority::HasHotpatches() const { return !hotpatches_.empty(); }

std::vector<ModelHotpatch> ProtocolAuthority::Hotpatches() const { return hotpatches_; }

void ProtocolAuthority::SetPuppeteerEnabled(bool on) { puppeteerEnabled_ = on; }

bool ProtocolAuthority::PuppeteerEnabled() const { return puppeteerEnabled_; }

Negotiation ProtocolAuthority::Negotiate(const ModelIdentity& id,
                                         NativeSupport probe) const {
    Negotiation n;
    n.nativeSupport = probe;
    n.puppeteerEnabled = puppeteerEnabled_;

    const ModelHotpatch* hp = FindHotpatch(hotpatches_, id);
    if (hp) {
        n.hotpatchId = hp->id;
        n.hotpatchApplied = true;
    }

    if (probe == NativeSupport::Pass) {
        n.tier = hp ? Tier::HotpatchAdapt : Tier::Native;
        n.preferred = Dialect::OpenAiToolCalls;
        n.reason = "probe observed a tool call in a dialect the model was trained to emit";
    } else if (probe == NativeSupport::Unsupported) {
        n.tier = hp ? Tier::HotpatchAdapt : Tier::Puppeteer;
        n.reason = hp ? ("probe disproved native tool calling; hotpatch " + hp->id +
                         " applied; runtime provides the protocol")
                      : "probe disproved native tool calling; runtime provides the protocol";
    } else {
        // Unmeasured is not the same as capable. An unmeasured model is
        // puppeteered, which costs a little strictness and buys participation.
        n.tier = hp ? Tier::HotpatchAdapt : Tier::Puppeteer;
        n.reason = hp ? ("unmeasured; hotpatch " + hp->id +
                         " applied; runtime provides the protocol")
                      : "unmeasured; an unmeasured model is puppeteered, not trusted";
    }
    if (!n.puppeteerEnabled && n.tier != Tier::Native) {
        n.reason += "; puppeteer tier disabled";
    }
    if (id.declaredNativeToolCalls && probe != NativeSupport::Pass) {
        n.reason += "; loader declared native tool calling and the probe did not confirm it";
    }

    // Search order: trained markers first (they are the most specific), then the
    // dialect RawrXD teaches, then runtime inference last so it can only act on
    // text no protocol scanner claimed.
    n.searchOrder = {
        Dialect::OpenAiToolCalls, Dialect::HermesToolCall, Dialect::QwenGlmToolCall,
        Dialect::Llama3PythonTag, Dialect::MistralToolCalls, Dialect::RawrToolBlock,
        Dialect::LegacyReAct};
    if (n.puppeteerEnabled) n.searchOrder.push_back(Dialect::InferredIntent);
    return n;
}

bool ProtocolAuthority::Validate(Intent& intent, const ToolDef& def) {
    for (const auto& p : def.params) {
        if (!p.required) continue;
        if (intent.args.find(p.name) == intent.args.end()) {
            intent.error = "missing_required_parameter:" + p.name;
            return false;
        }
    }
    for (const auto& kv : intent.args) {
        bool known = def.params.empty();
        for (const auto& p : def.params) {
            if (p.name == kv.first) { known = true; break; }
        }
        // An unrecognised argument is a warning, not a refusal: a model that
        // adds a comment is still making the call it made.
        if (!known) intent.warnings.push_back("unknown_argument:" + kv.first);
    }
    return true;
}

std::string ProtocolAuthority::BuildToolInstructions(const std::vector<ToolDef>& tools,
                                                    const Negotiation& n,
                                                    const ModelHotpatch* hp) {
    std::vector<ToolDef> sorted = tools;
    std::sort(sorted.begin(), sorted.end(),
              [](const ToolDef& a, const ToolDef& b) { return a.name < b.name; });

    std::ostringstream oss;
    if (n.tier == Tier::Native) {
        // Deliberately no grammar here. The model already has one, and
        // re-teaching a dialect is how a native model starts emitting the wrong
        // marker.
        oss << "You have access to the tools listed below. Call one using your own "
               "native tool-calling format, and put nothing but the call in that "
               "message.\n\n";
    } else {
        oss << "You can use the tools listed below.\n"
               "To use one, write a single line in this form and then stop:\n"
               "  tool_name(arg1=\"value\", arg2=\"value\")\n"
               "Rules:\n"
               "  - One tool line per reply, then stop and wait for the result.\n"
               "  - Use only tool names listed below.\n"
               "  - Write the line on its own. Do not quote it, do not describe it, "
               "and do not add commentary to the same line.\n"
               "  - After a result arrives, answer in plain text unless you need "
               "another tool.\n\n";
    }
    if (hp && !hp->notes.empty()) oss << hp->notes << "\n\n";

    for (const auto& def : sorted) {
        oss << "Tool: " << def.name << "\n" << def.description << "\n";
        if (!def.params.empty()) {
            oss << "Params:\n";
            for (const auto& p : def.params) {
                oss << "  " << p.name << " (" << p.type << ")"
                    << (p.required ? " [required]" : " [optional]") << ": " << p.description
                    << "\n";
            }
        }
        oss << "\n";
    }
    return oss.str();
}

std::string ProtocolAuthority::BuildObservation(const std::string& toolName,
                                                const std::string& argsJson,
                                                bool success, const std::string& output,
                                                Dialect dialect) {
    std::ostringstream head;
    head << "TOOL_RESULT " << toolName << " status=" << (success ? "OK" : "ERROR");
    if (!argsJson.empty()) head << " args=" << argsJson;
    const std::string body = head.str() + "\n" + output;

    // A model that emits <tool_call> was trained to see <tool_response> back.
    // Replaying a fixed format to a model that does not know that convention is
    // how a non-tool model ends up echoing markup into its answer.
    switch (dialect) {
        case Dialect::HermesToolCall:
            return "<tool_response>\n" + body + "\n</tool_response>";
        case Dialect::QwenGlmToolCall:
            return "<|observation|>\n" + body;
        case Dialect::MistralToolCalls:
            return "[TOOL_RESULTS] " + argsJson + "\n" + output;
        case Dialect::Llama3PythonTag:
        case Dialect::OpenAiToolCalls:
        case Dialect::RawrToolBlock:
        case Dialect::LegacyReAct:
        case Dialect::InferredIntent:
        case Dialect::None:
            return body;
    }
    return body;
}

NativeSupport ProtocolAuthority::ProbeNativeToolCalling(const std::string& modelReply,
                                                        Dialect* outDialect) {
    static const Dialect kTrained[] = {
        Dialect::OpenAiToolCalls, Dialect::HermesToolCall, Dialect::QwenGlmToolCall,
        Dialect::Llama3PythonTag, Dialect::MistralToolCalls};

    for (const Dialect d : kTrained) {
        for (const RawCall& rc : ScanDialect(d, modelReply, {})) {
            if (rc.error.empty() && !rc.name.empty()) {
                if (outDialect) *outDialect = d;
                return NativeSupport::Pass;
            }
        }
    }
    if (outDialect) *outDialect = Dialect::None;
    return NativeSupport::Unsupported;
}

std::string ProtocolAuthority::BuildNativeProbePrompt(const std::string& toolName,
                                                      const std::string& argName,
                                                      const std::string& argValue) {
    // NO_TOOL_PROTOCOL is an explicit escape. Without it a base model will
    // hallucinate a plausible call to satisfy the instruction, and the probe
    // would certify a model that cannot call tools.
    return "Call the tool `" + toolName + "` exactly once, with " + argName + "=\"" +
           argValue + "\", using your own native tool-calling format.\n"
           "Put nothing but the tool call in your reply.\n"
           "If you have no tool-calling facility, reply with exactly: NO_TOOL_PROTOCOL\n";
}

ExtractResult ProtocolAuthority::Extract(const ModelIdentity& id, const std::string& text,
                                         const std::vector<ToolDef>& tools) const {
    return Extract(Negotiate(id, NativeSupport::Undeclared), id, text, tools);
}

ExtractResult ProtocolAuthority::Extract(const Negotiation& n, const ModelIdentity& id,
                                         const std::string& text,
                                         const std::vector<ToolDef>& tools) const {
    (void)id;
    ExtractResult res;
    res.tier = n.tier;
    res.nativeSupport = n.nativeSupport;
    res.hotpatchId = n.hotpatchId;
    res.hotpatchApplied = n.hotpatchApplied;
    ++counters_.extractCalls;

    // Hotpatch first: a model that echoes <|im_start|> into its answer would
    // otherwise have that marker parsed as part of a tool call, or shown to the
    // user as content.
    std::string work = text;
    if (n.hotpatchApplied) {
        const ModelHotpatch* hp = FindHotpatch(hotpatches_, id);
        if (hp) {
            for (const std::string& marker : hp->outputStrips) {
                if (marker.empty()) continue;
                for (;;) {
                    const std::size_t at = work.find(marker);
                    if (at == std::string::npos) break;
                    work.erase(at, marker.size());
                    ++res.strippedMarkers;
                    ++counters_.markersStripped;
                }
            }
        }
        ++counters_.hotpatchApplications;
    }
    res.sanitizedText = work;

    std::vector<std::pair<Dialect, RawCall>> found;
    found.reserve(8);
    for (const Dialect d : n.searchOrder) {
        for (RawCall& rc : ScanDialect(d, work, tools)) found.emplace_back(d, std::move(rc));
    }

    std::vector<std::pair<std::size_t, std::size_t>> covered;
    const auto coveredBy = [&covered](std::size_t b, std::size_t e) {
        for (const auto& c : covered) {
            if (b >= c.first && e <= c.second) return true;
        }
        return false;
    };

    for (auto& f : found) {
        const Dialect d = f.first;
        RawCall& rc = f.second;
        if (rc.end <= rc.begin) rc.end = rc.begin + 1;
        // A later scanner must not re-find a call inside an accepted span. This
        // is what keeps the puppeteer from acting on text inside a native
        // marker.
        if (coveredBy(rc.begin, rc.end)) continue;

        Intent it;
        it.name = rc.name;
        it.dialect = d;
        it.agency = IsTrainedProtocolDialect(d) ? Agency::ModelNative
                   : (d == Dialect::InferredIntent ? Agency::RuntimeInferred
                                                  : Agency::ModelUnmarked);
        for (const auto& a : rc.args) {
            if (it.args.find(a.first) == it.args.end()) it.args[a.first] = a.second;
        }
        for (const std::string& w : rc.warnings) it.warnings.push_back(w);
        it.begin = rc.begin;
        it.end = rc.end;
        it.raw = rc.raw;

        // Every refusal is counted, whatever refused it. A counter that tallies
        // only the two paths it happened to notice reads 1 while seven
        // refusals happened, and a receipt that undercounts is worse than one
        // that fails loudly.
        const auto refuse = [&res, this](Intent& it) {
            ++counters_.intentsRejected;
            res.rejected.push_back(it);
        };

        if (!rc.error.empty()) { it.error = rc.error; refuse(it); continue; }
        if (it.name.empty()) { it.error = "no_tool_name"; refuse(it); continue; }

        const ToolDef* def = FindToolDef(tools, it.name);
        if (!def) {
            it.error = "not_a_registered_tool";
            refuse(it);
            continue;
        }
        if (!Validate(it, *def)) {
            refuse(it);
            continue;
        }

        covered.emplace_back(rc.begin, rc.end);
        res.accepted.push_back(it);
        ++counters_.intentsAccepted;
        switch (it.agency) {
            case Agency::ModelNative:     ++counters_.native; break;
            case Agency::ModelUnmarked:   ++counters_.unmarked; break;
            case Agency::RuntimeInferred: ++counters_.inferred; break;
        }
    }
    return res;
}

ProtocolAuthority::Counters ProtocolAuthority::GetCounters() const { return counters_; }

void ProtocolAuthority::ResetCounters() { counters_ = Counters(); }

std::string ProtocolAuthority::WriteReceipt(const std::string& dir,
                                            const ModelIdentity& id,
                                            const Negotiation& n,
                                            const ExtractResult& last) const {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return std::string();

    const std::string path = dir + "/" + std::string(GateName()) + "_LAST.ini";
    const Counters c = counters_;

    std::size_t acceptedNative = 0, acceptedUnmarked = 0, acceptedInferred = 0;
    for (const Intent& it : last.accepted) {
        switch (it.agency) {
            case Agency::ModelNative:     ++acceptedNative; break;
            case Agency::ModelUnmarked:   ++acceptedUnmarked; break;
            case Agency::RuntimeInferred: ++acceptedInferred; break;
        }
    }

    std::ostringstream oss;
    oss << "=== " << std::string(GateName()) + " ===\n";
    oss << "MODEL_NAME=" << (id.name.empty() ? "unnamed" : id.name) << "\n";
    oss << "MODEL_ARCH=" << (id.arch.empty() ? "unknown" : id.arch) << "\n";
    oss << "MODEL_TEMPLATE_FAMILY=" << (id.chatTemplateFamily.empty() ? "unknown"
                                                                    : id.chatTemplateFamily)
        << "\n";
    oss << "MODEL_KEY=" << id.key() << "\n";
    oss << "LOADER_DECLARED_NATIVE=" << (id.declaredNativeToolCalls ? 1 : 0) << "\n";
    oss << "NATIVE_TOOL_CALLING=" << ToString(n.nativeSupport) << "\n";
    oss << "TIER=" << ToString(n.tier) << "\n";
    oss << "TIER_REASON=" << n.reason << "\n";
    oss << "HOTPATCH_APPLIED=" << (n.hotpatchApplied ? 1 : 0) << "\n";
    oss << "HOTPATCH_ID=" << (n.hotpatchId.empty() ? "none" : n.hotpatchId) << "\n";
    oss << "PUPPETEER_ENABLED=" << (n.puppeteerEnabled ? 1 : 0) << "\n";
    oss << "DIALECT_SEARCH_ORDER=";
    for (std::size_t i = 0; i < n.searchOrder.size(); ++i) {
        if (i) oss << ",";
        oss << ToString(n.searchOrder[i]);
    }
    oss << "\n";
    oss << "HOTPATCHES_REGISTERED=" << hotpatches_.size() << "\n";
    oss << "TOOL_INTENTS_ACCEPTED=" << last.accepted.size() << "\n";
    oss << "TOOL_INTENTS_REJECTED=" << last.rejected.size() << "\n";
    oss << "TOOL_ARGUMENTS_VALID=";
    if (last.accepted.empty()) {
        oss << "NOT_MEASURED";
    } else {
        bool ok = true;
        for (const Intent& it : last.accepted) {
            if (it.rejected()) ok = false;
        }
        oss << (ok ? 1 : 0);
    }
    oss << "\n";
    oss << "AGENCY_ACCEPTED_NATIVE=" << acceptedNative << "\n";
    oss << "AGENCY_ACCEPTED_UNMARKED=" << acceptedUnmarked << "\n";
    oss << "AGENCY_ACCEPTED_INFERRED=" << acceptedInferred << "\n";
    oss << "SPECIAL_MARKERS_STRIPPED=" << last.strippedMarkers << "\n";
    for (const Intent& it : last.rejected) {
        oss << "REFUSED name=" << (it.name.empty() ? "?" : it.name)
            << " dialect=" << ToString(it.dialect) << " reason=" << it.error << "\n";
    }
    oss << "AUTHORITY_EXTRACT_CALLS=" << c.extractCalls << "\n";
    oss << "AUTHORITY_INTENTS_ACCEPTED=" << c.intentsAccepted << "\n";
    oss << "AUTHORITY_INTENTS_REJECTED=" << c.intentsRejected << "\n";
    oss << "AUTHORITY_AGENCY_NATIVE=" << c.native << "\n";
    oss << "AUTHORITY_AGENCY_UNMARKED=" << c.unmarked << "\n";
    oss << "AUTHORITY_AGENCY_INFERRED=" << c.inferred << "\n";
    oss << "AUTHORITY_HOTPATCH_APPLICATIONS=" << c.hotpatchApplications << "\n";
    oss << "AUTHORITY_MARKERS_STRIPPED=" << c.markersStripped << "\n";
    oss << "NOTE=AUTHORITY_* lines are runtime counters, never a verdict. A gate "
           "computes its verdict from its own observations.\n";
    oss << "=== RECEIPT_END ===\n";

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return std::string();
    f << oss.str();
    f.close();
    if (!f) return std::string();
    return path;
}

} // namespace mtproto
} // namespace agentic
} // namespace rawrxd
