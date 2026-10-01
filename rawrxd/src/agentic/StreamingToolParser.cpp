// ============================================================================
// StreamingToolParser.cpp — RAWRXD_AGENTIC_STREAMING_TOOL_PARSER_001
//
// Correctness properties this implementation provides, each of which the
// naive split-chunk version lacks:
//   1. A delimiter split across two chunks is still detected, because text is
//      drained only up to the last position where a delimiter prefix could
//      still begin. A marker is therefore never lost and never emitted as text.
//   2. Text following ">>>" in the same chunk is returned instead of discarded.
//   3. The parameter object is a real brace-depth JSON scanner with string and
//      escape awareness, so nested objects, escaped quotes and escaped braces
//      do not terminate the block early.
// ============================================================================
#include "agentic/StreamingToolParser.h"

#include <algorithm>
#include <cstring>

namespace rawrxd {
namespace agentic {
namespace {

// Longest suffix of `s` that is a strict prefix of `tag`. This is the amount of
// input that must be held back because it might still become a delimiter.
std::size_t LongestPartialTagMatch(const std::string& s, const std::string& tag) {
    if (tag.empty()) return 0;
    const std::size_t maxCandidate = std::min(s.size(), tag.size() - 1);
    for (std::size_t len = maxCandidate; len > 0; --len) {
        if (s.compare(s.size() - len, len, tag, 0, len) == 0) return len;
    }
    return 0;
}

bool IsSpace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

void AppendJsonEscaped(const std::string& in, std::string& out) {
    for (const char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    static const char* kHex = "0123456789abcdef";
                    out += "\\u00";
                    out += kHex[(static_cast<unsigned char>(c) >> 4) & 0x0F];
                    out += kHex[static_cast<unsigned char>(c) & 0x0F];
                } else {
                    out += c;
                }
                break;
        }
    }
}

// Reads a JSON string starting at the opening quote. Returns false when the
// string is unterminated or contains an invalid escape.
bool ReadJsonString(const std::string& s, std::size_t& pos, std::string& out, bool& badEscape) {
    if (pos >= s.size() || s[pos] != '"') return false;
    ++pos;
    out.clear();
    while (pos < s.size()) {
        const char c = s[pos];
        if (c == '"') {
            ++pos;
            return true;
        }
        if (c == '\\') {
            if (pos + 1 >= s.size()) {
                badEscape = true;
                return false;
            }
            const char esc = s[pos + 1];
            switch (esc) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'u': {
                    if (pos + 5 >= s.size()) {
                        badEscape = true;
                        return false;
                    }
                    unsigned code = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = s[pos + 2 + static_cast<std::size_t>(k)];
                        unsigned v = 0;
                        if (h >= '0' && h <= '9') v = static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') v = static_cast<unsigned>(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') v = static_cast<unsigned>(h - 'A' + 10);
                        else {
                            badEscape = true;
                            return false;
                        }
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
                    pos += 4;
                    break;
                }
                default:
                    badEscape = true;
                    return false;
            }
            pos += 2;
            continue;
        }
        out += c;
        ++pos;
    }
    return false;  // unterminated
}

// Reads a JSON scalar (number / true / false / null) and returns its raw text.
void ReadJsonScalar(const std::string& s, std::size_t& pos, std::string& out) {
    out.clear();
    while (pos < s.size()) {
        const char c = s[pos];
        if (c == ',' || c == '}' || c == ']' || IsSpace(c)) break;
        out += c;
        ++pos;
    }
}

// Skips a balanced object or array, string-aware.
void SkipJsonContainer(const std::string& s, std::size_t& pos) {
    int depth = 0;
    bool inString = false;
    while (pos < s.size()) {
        const char c = s[pos];
        if (inString) {
            if (c == '\\') {
                ++pos;
            } else if (c == '"') {
                inString = false;
            }
        } else if (c == '"') {
            inString = true;
        } else if (c == '{' || c == '[') {
            ++depth;
        } else if (c == '}' || c == ']') {
            --depth;
            if (depth == 0) {
                ++pos;
                return;
            }
        }
        ++pos;
    }
}

} // namespace

// ---------------------------------------------------------------------------

bool ToolCallEvent::HasParam(const std::string& key) const {
    return params.find(key) != params.end();
}

std::string ToolCallEvent::GetParam(const std::string& key) const {
    const auto it = params.find(key);
    return it == params.end() ? std::string() : it->second;
}

std::string ToolCallEvent::SerializeParamsJson() const {
    std::string out = "{";
    bool first = true;
    for (const auto& kv : orderedParams) {
        if (!first) out += ",";
        first = false;
        out += "\"";
        AppendJsonEscaped(kv.first, out);
        out += "\":\"";
        AppendJsonEscaped(kv.second, out);
        out += "\"";
    }
    out += "}";
    return out;
}

void StreamingToolParser::Reset() {
    state_ = State::Text;
    text_.clear();
    body_.clear();
    pendingTool_ = ToolCallEvent();
    lastStatus_ = ToolParseStatus::Ok;
    hasTool_ = false;
    totalBytesFed_ = 0;
    toolBlockCount_ = 0;
    malformedBlockCount_ = 0;
}

void StreamingToolParser::SetDelimiters(std::string openTag, std::string closeTag) {
    if (!openTag.empty()) openTag_ = std::move(openTag);
    if (!closeTag.empty()) closeTag_ = std::move(closeTag);
}

void StreamingToolParser::RecordMalformed(ToolParseStatus status) {
    lastStatus_ = status;
    ++malformedBlockCount_;
}

std::string StreamingToolParser::DrainText(bool atEndOfStream) {
    if (text_.empty()) return std::string();
    if (atEndOfStream) {
        std::string all;
        all.swap(text_);
        return all;
    }
    // Hold back only a suffix that could still grow into openTag_.
    const std::size_t hold = LongestPartialTagMatch(text_, openTag_);
    if (hold == 0) {
        std::string all;
        all.swap(text_);
        return all;
    }
    const std::size_t emitCount = text_.size() - hold;
    std::string out = text_.substr(0, emitCount);
    text_.erase(0, emitCount);
    return out;
}

void StreamingToolParser::ScanForOpenTag() {
    // Only valid when state_ == Text, which guarantees body_ is empty.
    // Everything after the open tag is tool-block content and must move into
    // body_, otherwise it would sit in text_ and later be emitted as assistant
    // prose.
    for (;;) {
        const std::size_t pos = text_.find(openTag_);
        if (pos == std::string::npos) return;
        // Skip the leading text AND the tag itself; everything after it is tool
        // body. Erasing only `pos` would leave the tag in the tool name.
        text_.erase(0, pos + openTag_.size());
        body_ = text_;
        text_.clear();
        state_ = State::ToolBody;
    }
}

void StreamingToolParser::CloseToolBlock() {
    const std::size_t closePos = body_.find(closeTag_);
    std::string block = body_.substr(0, closePos);
    body_.erase(0, closePos + closeTag_.size());

    // Anything after the closing tag is assistant text and must be returned to
    // the caller rather than silently dropped.
    text_ = body_ + text_;
    body_.clear();
    state_ = State::Text;

    ToolCallEvent event;
    std::string error;
    const ToolParseStatus status = ParseToolBlock(block, event, error);
    if (status == ToolParseStatus::Ok) {
        ++toolBlockCount_;
        lastStatus_ = status;
        pendingTool_ = event;
        hasTool_ = true;
    } else {
        RecordMalformed(status);
    }
}

FeedResult StreamingToolParser::Feed(const std::string& chunk) {
    FeedResult result;
    if (chunk.empty()) {
        result.inToolBlock = IsInToolBlock();
        return result;
    }
    totalBytesFed_ += chunk.size();

    // Route the chunk to whichever buffer the current state owns, then run the
    // close-detection loop unconditionally. Doing the loop only on the
    // "continuing a block" branch meant a whole tool block delivered in a single
    // chunk stayed open forever.
    if (state_ == State::ToolBody) {
        body_ += chunk;
    } else {
        text_ += chunk;
        ScanForOpenTag();
    }
    while (state_ == State::ToolBody && body_.find(closeTag_) != std::string::npos) {
        CloseToolBlock();
        if (state_ == State::Text) {
            ScanForOpenTag();
        }
    }

    if (state_ == State::Text) {
        const std::size_t before = text_.size();
        result.text = DrainText(false);
        result.textHeldBackBytes = before - result.text.size();
        result.textHeldBack = result.textHeldBackBytes > 0;
    }

    result.toolComplete = hasTool_;
    result.inToolBlock = IsInToolBlock();
    return result;
}

std::string StreamingToolParser::Finish() {
    if (state_ == State::ToolBody) {
        // Stream ended inside a tool block. Report it rather than emitting the
        // partial body as user-visible text.
        RecordMalformed(ToolParseStatus::Unterminated);
        body_.clear();
        state_ = State::Text;
    }
    return DrainText(true);
}

ToolCallEvent StreamingToolParser::ExtractTool() {
    hasTool_ = false;
    return pendingTool_;
}

ToolParseStatus StreamingToolParser::ParseToolBlock(const std::string& body, ToolCallEvent& out,
                                                    std::string& outError) {
    outError.clear();
    std::size_t pos = 0;
    while (pos < body.size() && IsSpace(body[pos])) ++pos;

    const std::size_t bar = body.find('|', pos);
    if (bar == std::string::npos) {
        outError = "no '|' separating tool name from parameters";
        return ToolParseStatus::NoSeparator;
    }

    std::string name = body.substr(pos, bar - pos);
    // Trim trailing whitespace from the name.
    while (!name.empty() && IsSpace(name.back())) name.pop_back();
    if (name.empty()) {
        outError = "empty tool name";
        return ToolParseStatus::EmptyName;
    }
    out.name = name;

    pos = bar + 1;
    while (pos < body.size() && IsSpace(body[pos])) ++pos;
    if (pos >= body.size()) {
        outError = "no parameter object after '|'";
        return ToolParseStatus::EmptyParams;
    }
    if (body[pos] != '{') {
        outError = "parameter block does not start with '{'";
        return ToolParseStatus::NoSeparator;
    }

    ++pos;  // consume '{'
    for (;;) {
        while (pos < body.size() && IsSpace(body[pos])) ++pos;
        if (pos >= body.size()) {
            outError = "unterminated parameter object";
            return ToolParseStatus::Unterminated;
        }
        if (body[pos] == '}') {
            ++pos;
            break;
        }

        std::string key;
        bool badEscape = false;
        if (!ReadJsonString(body, pos, key, badEscape)) {
            outError = badEscape ? "invalid escape in parameter name"
                                 : "unterminated parameter name";
            return badEscape ? ToolParseStatus::BadEscape : ToolParseStatus::UnterminatedString;
        }

        while (pos < body.size() && IsSpace(body[pos])) ++pos;
        if (pos >= body.size() || body[pos] != ':') {
            outError = "expected ':' after parameter name";
            return ToolParseStatus::NoSeparator;
        }
        ++pos;
        while (pos < body.size() && IsSpace(body[pos])) ++pos;
        if (pos >= body.size()) {
            outError = "missing parameter value";
            return ToolParseStatus::Unterminated;
        }

        std::string value;
        if (body[pos] == '"') {
            if (!ReadJsonString(body, pos, value, badEscape)) {
                outError = badEscape ? "invalid escape in parameter value"
                                     : "unterminated parameter value";
                return badEscape ? ToolParseStatus::BadEscape
                                 : ToolParseStatus::UnterminatedString;
            }
        } else if (body[pos] == '{' || body[pos] == '[') {
            // Nested structures are skipped; the executor only receives scalars.
            SkipJsonContainer(body, pos);
        } else {
            ReadJsonScalar(body, pos, value);
        }

        if (out.params.find(key) == out.params.end()) {
            out.orderedParams.emplace_back(key, value);
        }
        out.params[key] = value;

        while (pos < body.size() && IsSpace(body[pos])) ++pos;
        if (pos < body.size() && body[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < body.size() && body[pos] == '}') {
            ++pos;
            break;
        }
        if (pos >= body.size()) {
            outError = "unterminated parameter object";
            return ToolParseStatus::Unterminated;
        }
        outError = "expected ',' or '}' in parameter object";
        return ToolParseStatus::TrailingGarbage;
    }

    // Only whitespace may follow the closing brace.
    while (pos < body.size()) {
        if (!IsSpace(body[pos])) {
            outError = "unexpected characters after parameter object";
            return ToolParseStatus::TrailingGarbage;
        }
        ++pos;
    }
    return ToolParseStatus::Ok;
}

} // namespace agentic
} // namespace rawrxd
