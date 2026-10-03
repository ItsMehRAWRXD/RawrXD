// ============================================================================
// AgentBridge.hpp
//
// RAWRXD_AGENT_BRIDGE_001
//
// The narrow bridge that makes every model speak ONE ToolIntent, sends it into
// the already-proven ShellAuthority, and returns the authority's measured
// observation.
//
// ---------------------------------------------------------------------------
// WHY BOTH MODEL CLASSES TERMINATE HERE
// ---------------------------------------------------------------------------
//     NATIVE TOOL CALL ----.
//                          >--- ToolIntent --- AgentBridge --- ShellAction
//     PUPPETEER / HOTPATCH-'                                   |
//                                                             v
//                                                       ShellAuthority
//
//     NATIVE_AND_PUPPETEERED_TERMINATE_AT_SAME_AGENT_BRIDGE = 1
//     SECOND_SHELL_DISPATCHER                              = 0
//
// If a puppeteered model could reach the browser by its own route, puppeteering
// would be a second authority rather than a compatibility layer. So:
//     PUPPETEER_CAN_CREATE_TOOL_INTENT   = 1
//     PUPPETEER_CAN_EXECUTE_TOOL_DIRECTLY = 0
//
// ---------------------------------------------------------------------------
// THE BRIDGE IS INTENTIONALLY BORING
// ---------------------------------------------------------------------------
// It normalizes an intent into a ShellAction and calls ShellAuthority. It does
// NOT:
//
//   * speak CDP
//   * touch the filesystem
//   * open a browser
//   * recompute any verdict -- not browser, not files, not reverse receipt
//
//     AGENT_BRIDGE_DERIVES_BROWSER_VERDICT    = 0
//     AGENT_BRIDGE_DERIVES_FILE_VERDICT       = 0
//     AGENT_BRIDGE_REDERIVES_REVERSE_RECEIPT  = 0
//
// Every verdict in the result came out of an authority. The bridge only maps
// one enum to another and copies strings.
//
// ---------------------------------------------------------------------------
// THE MODEL CANNOT DECLARE SUCCESS
// ---------------------------------------------------------------------------
//     MODEL_CAN_DECLARE_TOOL_SUCCESS = 0
//     AUTHORITY_RECEIPT_DETERMINES_TOOL_SUCCESS = 1
//
// A model that emits "verdict=PASS" in its tool text changes nothing: the
// observation reports the ShellAuthority's derived verdict. `agentClaimedPass`
// is recorded only so the receipt can show the claim and the authority
// disagreeing, which is the falsification this design must survive.
// ============================================================================

#ifndef RAWRXD_AGENT_AGENT_BRIDGE_HPP
#define RAWRXD_AGENT_AGENT_BRIDGE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "shell/ShellAuthority.hpp"

namespace rawrxd::agent {

enum class ToolIntentSource { NativeToolCall, Puppeteered, Hotpatched };

inline const char* toolIntentSourceName(ToolIntentSource s) {
    switch (s) {
        case ToolIntentSource::NativeToolCall: return "NATIVE";
        case ToolIntentSource::Puppeteered:   return "PUPPETEERED";
        case ToolIntentSource::Hotpatched:    return "HOTPATCHED";
    }
    return "?";
}

enum class ToolIntentKind { Shell, AskUser, Complete };

inline const char* toolIntentKindName(ToolIntentKind k) {
    switch (k) {
        case ToolIntentKind::Shell:    return "SHELL";
        case ToolIntentKind::AskUser:  return "ASK_USER";
        case ToolIntentKind::Complete: return "COMPLETE";
    }
    return "?";
}

// Model-neutral. No model syntax crosses this boundary.
//
//   TOOL_INTENT_TARGET  = OBJECT
//   TOOL_INTENT_PAYLOAD = PARAMETERS
struct ToolIntent {
    std::uint64_t      sequence = 0;
    ToolIntentSource   source = ToolIntentSource::Puppeteered;
    ToolIntentKind     kind   = ToolIntentKind::Shell;

    std::string surface;     // "app://browser"
    std::string operation;   // "CLICK"
    std::string target;      // object identity
    std::string payload;     // parameters only
};

enum class AgentVerdict { Fail, Unproven, Pass };

inline const char* agentVerdictName(AgentVerdict v) {
    switch (v) {
        case AgentVerdict::Fail:     return "FAIL";
        case AgentVerdict::Unproven: return "UNPROVEN";
        case AgentVerdict::Pass:     return "PASS";
    }
    return "?";
}

// What the model is shown. Measured values only.
struct AgentObservation {
    std::uint64_t sequence = 0;

    std::string surface;
    std::string operation;
    std::string target;

    std::string result;        // the authority's measured after-state
    std::string detail;

    bool intentProduced = false;   // did anything parse an intent at all
    bool actionExecuted = false;   // shell dispatched it
    bool evidencePresent = false;  // the authority produced a verdict

    // What the model CLAIMED, kept only to show the authority overriding it.
    bool agentClaimedPass = false;
    std::string agentClaimedText;

    AgentVerdict verdict = AgentVerdict::Unproven;
};

struct AgentDispatchResult {
    ToolIntent      intent;
    AgentObservation observation;
    std::uint64_t   shellSequence = 0;
    std::string     surfaceDetail;
};

// ---------------------------------------------------------------------------
// Adapter: native structured tool call -> ToolIntent. NORMALIZATION ONLY.
// ---------------------------------------------------------------------------
class NativeToolIntentAdapter {
public:
    // Accepts a structured call the model natively produced, in either
    // JSON-ish or key=value form. Returns false when nothing parses -- and it
    // never invents a surface, operation or target.
    static bool parse(const std::string& raw, ToolIntent& out);
};

// ---------------------------------------------------------------------------
// Adapter: raw model text -> ToolIntent (the puppeteering/hotpatch path).
// ---------------------------------------------------------------------------
class PuppeteerToolIntentAdapter {
public:
    // Recognizes an executable intent inside ordinary generated text.
    //
    // Several surface forms are accepted because a small local model rarely
    // matches one template exactly. That is a robustness measure, not a licence:
    // when NOTHING matches, this returns false and the observation records that
    // no intent was produced. The adapter cannot invent an intent.
    static bool parse(const std::string& raw, ToolIntent& out);

    // Did the raw text claim success? Recorded ONLY so a receipt can show the
    // authority contradicting the model. It has no effect on any verdict.
    static bool claimsPass(const std::string& raw);

    // Normalizes model text into the tool-result text handed back to the model.
    // Contains only measured values.
    static std::string renderObservation(const AgentObservation& obs);
};

// ---------------------------------------------------------------------------
// The bridge
// ---------------------------------------------------------------------------
class AgentBridge {
public:
    explicit AgentBridge(rawrxd::shell::ShellAuthority& shell) noexcept
        : shell_(shell) {}

    // The entire bridge. No branches on surface kind, no I/O of its own.
    AgentDispatchResult dispatch(const ToolIntent& intent);

    // Convenience: normalize then dispatch, recording whether an intent was
    // produced at all. `claimedText` is the model's raw output, used only for
    // the claim-vs-authority comparison.
    AgentDispatchResult dispatchRaw(const std::string& rawModelText,
                                    ToolIntentSource source);

private:
    rawrxd::shell::ShellAuthority& shell_;
};

} // namespace rawrxd::agent

#endif // RAWRXD_AGENT_AGENT_BRIDGE_HPP