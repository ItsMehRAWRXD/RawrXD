// ============================================================================
// StreamingToolParser.h — RAWRXD_AGENTIC_STREAMING_TOOL_PARSER_001
// Incremental tool-call detection over a token stream, with no JSON library.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd {
namespace agentic {

// A parsed tool invocation. `params` preserves insertion order so a re-serialised
// tool call is byte-stable for the next turn.
struct ToolCallEvent {
    std::string name;
    std::vector<std::pair<std::string, std::string>> orderedParams;
    std::unordered_map<std::string, std::string> params;

    bool HasParam(const std::string& key) const;
    std::string GetParam(const std::string& key) const;
    // Canonical `{"k":"v",...}` rendering, escapes included.
    std::string SerializeParamsJson() const;
};

// Outcome of attempting to interpret a tool block.
enum class ToolParseStatus {
    Ok,
    NoSeparator,      // no '|' between name and parameter object
    EmptyName,
    Unterminated,     // no closing '}' for the parameter object
    TrailingGarbage,  // characters after the closing brace that are not '>>>'
    EmptyParams,      // "{}" is accepted as a no-argument call
    BadEscape,
    UnterminatedString,
};

// Result of a single Feed() call.
struct FeedResult {
    std::string text;                 // assistant text safe to emit to the user
    bool toolComplete = false;        // a whole tool block closed during this call
    bool inToolBlock = false;         // parser is mid-block after this call
    bool textHeldBack = false;        // text withheld because it may be a prefix
    std::size_t textHeldBackBytes = 0;
};

class StreamingToolParser {
public:
    // "<<<TOOL:" and ">>>" delimiters are configurable so a different model
    // template can be adopted without changing the state machine.
    void Reset();
    void SetDelimiters(std::string openTag, std::string closeTag);

    // Consumes one streamed chunk. Returns text that is guaranteed not to be
    // part of a tool block, so the caller can forward it immediately.
    FeedResult Feed(const std::string& chunk);

    bool HasPendingTool() const { return hasTool_; }
    const ToolCallEvent& PeekTool() const { return pendingTool_; }
    ToolCallEvent ExtractTool();

    bool IsInToolBlock() const { return state_ != State::Text; }
    ToolParseStatus LastStatus() const { return lastStatus_; }

    // Any bytes withheld because they might be a delimiter prefix. The caller
    // should flush this on end-of-stream via Finish().
    std::string Finish();

    // Total bytes fed, and how many were recognised as tool syntax.
    std::uint64_t TotalBytesFed() const { return totalBytesFed_; }
    std::uint64_t ToolBlockCount() const { return toolBlockCount_; }
    std::uint32_t MalformedBlockCount() const { return malformedBlockCount_; }

private:
    enum class State { Text, ToolBody };

    // Emits as much of `text_` as cannot be the start of openTag_.
    std::string DrainText(bool atEndOfStream);
    void ScanForOpenTag();
    void CloseToolBlock();
    void RecordMalformed(ToolParseStatus status);

    static ToolParseStatus ParseToolBlock(const std::string& body, ToolCallEvent& out,
                                          std::string& outError);

    State state_ = State::Text;
    std::string text_;
    std::string body_;
    std::string openTag_ = "<<<TOOL:";
    std::string closeTag_ = ">>>";
    ToolCallEvent pendingTool_;
    ToolParseStatus lastStatus_ = ToolParseStatus::Ok;
    bool hasTool_ = false;
    std::uint64_t totalBytesFed_ = 0;
    std::uint64_t toolBlockCount_ = 0;
    std::uint32_t malformedBlockCount_ = 0;
};

} // namespace agentic
} // namespace rawrxd
