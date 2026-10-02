// ============================================================================
// ModelToolProtocol.h — RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
//
// The design rule this file exists to enforce:
//
//     A model does not need native function-calling training to take part in
//     the RawrXD agent loop. The RUNTIME provides the protocol.
//
// RawrXD previously taught exactly one dialect (<<<TOOL:name|{json}>>>) to
// every model and assumed every model would comply. A model that was never
// trained on that convention simply never emits a tool block, the turn loop
// sees no tool call, and the agent silently degrades to a chat completion.
// That is a capability gap, not a bug, so it is closed here as a capability.
//
// Three tiers, selected from evidence rather than assumption:
//
//   NATIVE      a live probe confirmed the model emits its own trained
//               tool-call markers. RawrXD teaches nothing and only parses.
//   PUPPETEER   no trained protocol (or a probe disproved one). RawrXD
//               extracts a bounded, validated tool intent from ordinary text.
//   HOTPATCH    PUPPETEER plus a registered, model-keyed adaptation for a
//               model that is known to be incompatible or quirky.
//
// The honesty boundary, encoded in types rather than in a comment:
//
//   Agency::ModelNative    the marker came from the model's own training
//   Agency::ModelUnmarked  a convention RawrXD taught and the model followed
//   Agency::RuntimeInferred RawrXD inferred the call from ordinary prose
//
// ProbeNativeToolCalling() cannot return NativeSupport::Pass for a dialect
// RawrXD taught, because a taught dialect is by definition not native. A gate
// that cannot disagree is not a gate, so the probe is written to disagree.
//
// The legacy single-dialect streaming parser (agentic/StreamingToolParser.h)
// is left intact and still owns the Rawr dialect on the streaming path; this
// authority owns every other dialect plus the puppeteer tier.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "agentic/AgentToolRegistry.h"

namespace rawrxd {
namespace agentic {
namespace mtproto {

// --------------------------------------------------------------------------
// Enumerations
// --------------------------------------------------------------------------

enum class Tier : std::uint8_t {
    Unsupported = 0,  // no tier can serve this model
    Puppeteer,        // runtime provides the protocol; intent is extracted
    HotpatchAdapt,    // Puppeteer + a registered model-keyed hotpatch
    Native,           // probe MEASURED the model's own trained tool protocol
};

enum class Dialect : std::uint8_t {
    None = 0,
    RawrToolBlock,     // <<<TOOL:name|{"k":"v"}>>>        (taught by RawrXD)
    OpenAiToolCalls,   // {"tool_calls":[{"function":{...}}]}
    HermesToolCall,    // <tool_call>{"name":..,"arguments":{..}}</tool_call>
    QwenGlmToolCall,   // <|tool_call_start|>{..}<|tool_call_end|>
    Llama3PythonTag,   // <|python_tag|>{"type":"function","name":..}
    MistralToolCalls,  // [TOOL_CALLS] [{"name":..,"arguments":{..}}]
    LegacyReAct,       // Action: name / Action Input: {...}
    InferredIntent,    // runtime-inferred from ordinary prose
};

enum class Agency : std::uint8_t {
    ModelNative = 0,    // marker came from the model's own trained protocol
    ModelUnmarked,      // a dialect RawrXD taught; convention, not training
    RuntimeInferred,    // RawrXD inferred the call from ordinary text
};

enum class NativeSupport : std::uint8_t {
    Undeclared = 0,  // nobody measured it; the loader's claim is not evidence
    Pass,            // a live probe produced a trained-protocol tool call
    Unsupported,     // a live probe ran and the model did not comply
};

const char* ToString(Tier v) noexcept;
const char* ToString(Dialect v) noexcept;
const char* ToString(Agency v) noexcept;
const char* ToString(NativeSupport v) noexcept;

// Every dialect whose marker the MODEL was trained to emit. Dialects RawrXD
// teaches (RawrToolBlock, LegacyReAct) and dialects RawrXD infers
// (InferredIntent) are deliberately excluded: a taught convention must never be
// able to report itself as native support.
bool IsTrainedProtocolDialect(Dialect d) noexcept;

// --------------------------------------------------------------------------
// Model identity and hotpatches
// --------------------------------------------------------------------------

struct ModelIdentity {
    std::string name;               // GGUF key / file stem, for a human
    std::string arch;               // GGUF general.architecture
    std::string chatTemplateFamily; // llama3 | chatml | hermes | mistral-instruct | ...
    // A claim made by the loader or the operator. It is NOT evidence: it is
    // carried only so the receipt can show a declared claim that the probe
    // contradicted.
    bool declaredNativeToolCalls = false;

    // "arch/family", lowercased, for hotpatch lookup. Empty components collapse
    // to "*" so a hotpatch can key on architecture alone.
    std::string key() const;
};

struct ModelHotpatch {
    std::string id;      // HOTPATCH_ID recorded in the receipt
    std::string modelKey;  // "arch/family", "arch/*", "* /family", or "*/*"
    // Special markers removed from model OUTPUT before parsing and before the
    // text is shown to the user. This is the measured fix for a model that
    // echoes <|im_start|>/<|eot_id|> into its answer.
    std::vector<std::string> outputStrips;
    // Applied to the assembled prompt before it reaches the model.
    std::vector<std::pair<std::string, std::string>> promptRewrites;
    std::string notes;
};

// --------------------------------------------------------------------------
// Extracted intent
// --------------------------------------------------------------------------

struct Intent {
    std::string name;
    std::unordered_map<std::string, std::string> args;
    Dialect dialect = Dialect::None;
    Agency agency = Agency::RuntimeInferred;
    std::size_t begin = 0;  // span of the call inside the source text
    std::size_t end = 0;
    std::string raw;        // the exact text the intent was taken from
    // Non-empty means REFUSED. A refused intent is never executed; it exists so
    // a refusal is a measurement instead of silence.
    std::string error;
    std::vector<std::string> warnings;

    bool rejected() const noexcept { return !error.empty(); }
};

struct ExtractResult {
    std::vector<Intent> accepted;  // safe to execute
    std::vector<Intent> rejected;  // measured refusals
    std::string sanitizedText;     // model output after hotpatch stripping
    std::size_t strippedMarkers = 0;
    std::string hotpatchId;
    bool hotpatchApplied = false;
    Tier tier = Tier::Unsupported;
    NativeSupport nativeSupport = NativeSupport::Undeclared;
};

struct Negotiation {
    Tier tier = Tier::Unsupported;
    NativeSupport nativeSupport = NativeSupport::Undeclared;
    Dialect preferred = Dialect::RawrToolBlock;
    std::vector<Dialect> searchOrder;
    std::string hotpatchId;
    bool hotpatchApplied = false;
    bool puppeteerEnabled = true;
    std::string reason;  // why this tier; carried into the receipt verbatim
};

// --------------------------------------------------------------------------
// The authority
// --------------------------------------------------------------------------

class ProtocolAuthority {
public:
    static ProtocolAuthority& Instance();

    // -- hotpatch registry ---------------------------------------------------
    void RegisterHotpatch(const ModelHotpatch& hp);
    bool UnregisterHotpatch(const std::string& id);
    void ClearHotpatches();
    bool HasHotpatches() const;
    std::vector<ModelHotpatch> Hotpatches() const;

    // Global kill switch for the puppeteer tier. The falsification probe sets
    // it false and requires every inferred case to produce nothing, which is
    // what proves the tier is what produced the earlier results.
    void SetPuppeteerEnabled(bool on);
    bool PuppeteerEnabled() const;

    // -- the decision --------------------------------------------------------
    //
    // `probe` is the measured result from ProbeNativeToolCalling. Passing
    // Undeclared never yields Tier::Native, so an unmeasured model is
    // puppeteered rather than trusted.
    Negotiation Negotiate(const ModelIdentity& id, NativeSupport probe) const;

    // -- the parse -----------------------------------------------------------
    //
    // The ModelIdentity form negotiates with NativeSupport::Undeclared, so it
    // can never reach Tier::Native and can never over-claim native support. A
    // caller that has run a probe uses the Negotiation form.
    ExtractResult Extract(const ModelIdentity& id, const std::string& text,
                          const std::vector<ToolDef>& tools) const;
    ExtractResult Extract(const Negotiation& n, const ModelIdentity& id,
                          const std::string& text,
                          const std::vector<ToolDef>& tools) const;

    // Applies an intent's arguments to a tool definition. Fills `error` and
    // returns false on refusal. Unknown arguments are a warning, not a
    // refusal, because a model that adds a comment is still making the call.
    static bool Validate(Intent& intent, const ToolDef& def);

    // -- the protocol handed to the model ------------------------------------
    //
    // Never asserts native support. A Native-tier prompt is empty of protocol
    // text on purpose: the model already has one, and re-teaching it is how a
    // native model gets taught a dialect and starts emitting the wrong one.
    static std::string BuildToolInstructions(const std::vector<ToolDef>& tools,
                                             const Negotiation& n,
                                             const ModelHotpatch* hp = nullptr);

    // -- the observation handed back -----------------------------------------
    //
    // Dialect-aware on purpose: a Hermes-trained model expects
    // <tool_response>, a Qwen/GLM model expects <|observation|>, and a
    // puppeteered model is best served by plain text. Replaying one fixed
    // format to every model is how a non-tool model ends up echoing markup.
    static std::string BuildObservation(const std::string& toolName,
                                        const std::string& argsJson,
                                        bool success,
                                        const std::string& output,
                                        Dialect dialect);

    // -- the measurement -----------------------------------------------------
    //
    // Passes `modelReply` and returns whether it contains a tool call in a
    // dialect the MODEL was trained to emit. A taught or inferred dialect
    // cannot produce Pass. That constraint is the whole point: it is what
    // separates "the runtime taught it" from "the model knows how".
    static NativeSupport ProbeNativeToolCalling(const std::string& modelReply,
                                                Dialect* outDialect = nullptr);

    // The probe prompt. Exposed so a caller runs a real model rather than
    // inventing a result.
    static std::string BuildNativeProbePrompt(const std::string& toolName,
                                             const std::string& argName,
                                             const std::string& argValue);

    // -- runtime evidence counters ------------------------------------------
    // These are for receipts and forensics. A gate verdict must be computed
    // from its own observations, never read back out of here.
    struct Counters {
        std::uint64_t extractCalls = 0;
        std::uint64_t intentsAccepted = 0;
        std::uint64_t intentsRejected = 0;
        std::uint64_t native = 0;
        std::uint64_t unmarked = 0;
        std::uint64_t inferred = 0;
        std::uint64_t hotpatchApplications = 0;
        std::uint64_t markersStripped = 0;
    };
    Counters GetCounters() const;
    void ResetCounters();

    // Writes the ini receipt. Returns the path written, or "" on failure.
    std::string WriteReceipt(const std::string& dir, const ModelIdentity& id,
                             const Negotiation& n, const ExtractResult& last) const;

    static const char* GateName() { return "RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001"; }

private:
    ProtocolAuthority() = default;

    std::vector<ModelHotpatch> hotpatches_;
    bool puppeteerEnabled_ = true;
    mutable Counters counters_;
};

} // namespace mtproto
} // namespace agentic
} // namespace rawrxd
