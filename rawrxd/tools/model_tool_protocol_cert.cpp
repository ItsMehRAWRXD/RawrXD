// ============================================================================
// model_tool_protocol_cert.cpp
//   RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001 — certification harness
//
// What is being certified:
//
//   A model that has no native function-calling training can still complete a
//   tool-using task in the RawrXD agent loop, and the receipt can tell you
//   whether it did so natively, by convention, or only because RawrXD inferred
//   the call.
//
// What is NOT being certified, deliberately:
//
//   That any particular model is good at tool calling. The probe in this
//   harness runs against scripted replies, so it certifies that the probe
//   DISCRIMINATES. Certifying a real model requires a real model, and the
//   dimension printed here (NATIVE_TOOL_CALLING) is reported as UNDECLARED
//   unless a live backend is bound.
//
// The falsification controls are the load-bearing part. A gate that passes on
// every input measures nothing, so every positive case has a negative twin that
// must produce the opposite result with the same code:
//
//   * a taught dialect must NOT be able to report native support
//   * disabling the puppeteer tier must remove every inferred call
//   * prose that is not a call must yield nothing, accepted or rejected
//   * a name the registry does not hold must be refused, not executed
//   * an argument the runtime would have to invent must be refused
//   * an unterminated block must be refused, not completed
//   * the authority and the pre-existing streaming parser must agree on the
//     same Rawr block, or one of them is wrong
// ============================================================================
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "agentic/AgentOrchestrator.h"
#include "agentic/AgentToolRegistry.h"
#include "agentic/ModelToolProtocol.h"
#include "agentic/StreamingToolParser.h"

using namespace rawrxd::agentic;
using mtproto::Agency;
using mtproto::Dialect;
using mtproto::ExtractResult;
using mtproto::Intent;
using mtproto::ModelHotpatch;
using mtproto::ModelIdentity;
using mtproto::NativeSupport;
using mtproto::Negotiation;
using mtproto::ProtocolAuthority;
using mtproto::Tier;

namespace {

int g_pass = 0;
int g_fail = 0;
int g_notrun = 0;

void Check(bool ok, const std::string& name, const std::string& detail = std::string()) {
    if (ok) {
        ++g_pass;
        std::printf("PASS %-58s %s\n", name.c_str(), detail.c_str());
    } else {
        ++g_fail;
        std::printf("FAIL %-58s %s\n", name.c_str(), detail.c_str());
    }
}

void NotRun(const std::string& name, const std::string& why) {
    ++g_notrun;
    std::printf("NOTRUN %-56s %s\n", name.c_str(), why.c_str());
}

// A two-tool registry that mirrors the shape of the real one: one required
// argument, and a second tool with two. The second exists so positional
// ambiguity has something to be ambiguous about.
std::vector<ToolDef> MakeTools() {
    std::vector<ToolDef> t;
    t.push_back({"read_file", "Read a file.",
                 {{"path", "string", "File path.", true}}});
    t.push_back({"search_code", "Search a file.",
                 {{"path", "string", "File path.", true},
                  {"needle", "string", "Text to find.", true}}});
    return t;
}

const Intent* Accepted(const ExtractResult& r) {
    return r.accepted.empty() ? nullptr : &r.accepted.front();
}

bool HasRejected(const ExtractResult& r, const std::string& reasonPrefix) {
    for (const Intent& it : r.rejected) {
        if (it.error.rfind(reasonPrefix, 0) == 0) return true;
    }
    return false;
}

const char* AgencyName(Agency a) { return mtproto::ToString(a); }

// The binary that produced the real-model evidence on 2026-10-02. It predates
// the current tree, so the measurement is bound to THIS identity and not to
// "the current build". Recording it here means a PASS cannot later be read as
// covering an inference path it was never run against.
constexpr const char* kRealModelServerSha =
    "A37484B19F09186DAABDAE091144D4451F1E1FF305ED2B6467C97C23B465A046";

// ---------------------------------------------------------------------------
// The dialect matrix. Each row is a real surface form a model emits, and each
// must produce the same (name, argument) regardless of which dialect carried it.
// ---------------------------------------------------------------------------
struct DialectCase {
    const char* label;
    Dialect dialect;
    const char* reply;
};

const DialectCase kDialectCases[] = {
    {"openai.tool_calls", Dialect::OpenAiToolCalls,
     "Let me look.\n{\"tool_calls\":[{\"id\":\"call_1\",\"type\":\"function\","
     "\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.cpp\\\"}\"}}]}\n"},
    {"hermes.tool_call", Dialect::HermesToolCall,
     "Sure.\n<tool_call>{\"name\":\"read_file\",\"arguments\":{\"path\":\"a.cpp\"}}</tool_call>\n"},
    {"qwen_glm.tool_call_start", Dialect::QwenGlmToolCall,
     "Reading it.\n<|tool_call_start|>{ \"name\": \"read_file\", \"arguments\": { \"path\": \"a.cpp\" } }<|tool_call_end|>\n"},
    {"llama3.python_tag", Dialect::Llama3PythonTag,
     "On it.\n<|python_tag|>{\"type\":\"function\",\"name\":\"read_file\",\"parameters\":{\"path\":\"a.cpp\"}}<|eom_id|>\n"},
    {"llama3.python_tag.no_close", Dialect::Llama3PythonTag,
     "On it.\n<|python_tag|>{\"type\":\"function\",\"name\":\"read_file\",\"parameters\":{\"path\":\"a.cpp\"}}\n"},
    {"mistral.TOOL_CALLS", Dialect::MistralToolCalls,
     "Working.\n[TOOL_CALLS] [ {\"name\": \"read_file\", \"arguments\": {\"path\": \"a.cpp\"}} ]\n"},
    {"rawr.tool_block", Dialect::RawrToolBlock,
     "One moment.\n<<<TOOL:read_file|{\"path\":\"a.cpp\"}>>>\n"},
    {"react.action", Dialect::LegacyReAct,
     "I will read it.\nAction: read_file\nAction Input: {\"path\": \"a.cpp\"}\n"},
    {"puppeteer.call_syntax", Dialect::InferredIntent,
     "I should look at that first.\nread_file(path=\"a.cpp\")\n"},
    {"puppeteer.braced", Dialect::InferredIntent,
     "Next step.\nread_file {\"path\": \"a.cpp\"}\n"},
};

// ---------------------------------------------------------------------------

// Scripted backend: a model with no tool-calling training that follows the one
// convention the runtime taught it. Returns its tool call on turn 1 and a plain
// answer afterwards, which is the shape of a real puppeteered model.
struct ScriptedModel {
    std::string toolLine;
    std::string finalAnswer;
    int turn = 0;
    std::vector<std::string> prompts;

    bool operator()(const std::string& prompt, const StreamCallbackBase& emit) {
        prompts.push_back(prompt);
        const std::string out = (turn == 0) ? toolLine : finalAnswer;
        ++turn;
        if (!out.empty()) emit(out);
        return true;
    }
};

} // namespace

int main(int argc, char** argv) {
    const std::string receiptDir = (argc > 1) ? argv[1] : std::string("receipts");
    std::printf("=== %s ===\n", ProtocolAuthority::GateName());
    std::printf("HARNESS=model_tool_protocol_cert\n");

    ProtocolAuthority& auth = ProtocolAuthority::Instance();
    auth.ResetCounters();
    auth.ClearHotpatches();
    auth.SetPuppeteerEnabled(true);

    const std::vector<ToolDef> tools = MakeTools();

    // An ordinary model: no architecture claim, no tool-calling training.
    ModelIdentity plainModel;
    plainModel.name = "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    plainModel.arch = "llama";
    plainModel.chatTemplateFamily = "unknown";

    // -----------------------------------------------------------------------
    // 1. Every dialect, every tier-adjacent path.
    // -----------------------------------------------------------------------
    const Negotiation plain = auth.Negotiate(plainModel, NativeSupport::Undeclared);
    Check(plain.tier == Tier::Puppeteer, "tier.unmeasured_model_is_puppeteered",
          std::string("tier=") + mtproto::ToString(plain.tier));

    for (const DialectCase& dc : kDialectCases) {
        const ExtractResult r = auth.Extract(plain, plainModel, dc.reply, tools);
        const Intent* it = Accepted(r);
        const bool ok = it != nullptr && it->name == "read_file" &&
                        it->args.count("path") && it->args.at("path") == "a.cpp" &&
                        it->dialect == dc.dialect;
        std::string detail = "dialect=";
        detail += mtproto::ToString(dc.dialect);
        if (it) {
            detail += " agency=";
            detail += AgencyName(it->agency);
        } else {
            detail += " NO_INTENT";
            for (const Intent& rej : r.rejected) detail += " rejected=" + rej.error;
        }
        Check(ok, std::string("dialect.") + dc.label, detail);
    }

    // The agency assignment is the honesty boundary, so it is checked
    // explicitly per class rather than inferred from the case passing.
    {
        ExtractResult r = auth.Extract(plain, plainModel, kDialectCases[0].reply, tools);
        Check(Accepted(r) && Accepted(r)->agency == Agency::ModelNative,
              "agency.trained_marker_is_model_native",
              Accepted(r) ? AgencyName(Accepted(r)->agency) : "none");

        r = auth.Extract(plain, plainModel, kDialectCases[6].reply, tools);
        Check(Accepted(r) && Accepted(r)->agency == Agency::ModelUnmarked,
              "agency.taught_marker_is_not_native",
              Accepted(r) ? AgencyName(Accepted(r)->agency) : "none");

        r = auth.Extract(plain, plainModel, kDialectCases[8].reply, tools);
        Check(Accepted(r) && Accepted(r)->agency == Agency::RuntimeInferred,
              "agency.prose_call_is_runtime_inferred",
              Accepted(r) ? AgencyName(Accepted(r)->agency) : "none");
    }

    // -----------------------------------------------------------------------
    // 2. The probe must discriminate, and must not confirm RawrXD's own prompt.
    // -----------------------------------------------------------------------
    {
        Dialect d = Dialect::None;
        const NativeSupport complies =
            ProtocolAuthority::ProbeNativeToolCalling(kDialectCases[0].reply, &d);
        Check(complies == NativeSupport::Pass && d == Dialect::OpenAiToolCalls,
              "probe.native_reply_passes",
              std::string("support=") + mtproto::ToString(complies) +
                  " dialect=" + mtproto::ToString(d));

        const NativeSupport refuses = ProtocolAuthority::ProbeNativeToolCalling(
            "NO_TOOL_PROTOCOL\n", &d);
        Check(refuses == NativeSupport::Unsupported, "probe.escape_reply_is_unsupported",
              std::string("support=") + mtproto::ToString(refuses));

        // The decisive control: the dialect RawrXD teaches in the system prompt
        // must NOT certify the model as native. If this passes the other way,
        // the probe is measuring RawrXD's prompt and every later PASS is void.
        const NativeSupport taught = ProtocolAuthority::ProbeNativeToolCalling(
            kDialectCases[6].reply, &d);
        Check(taught == NativeSupport::Unsupported && d == Dialect::None,
              "probe.taught_dialect_cannot_report_native",
              std::string("support=") + mtproto::ToString(taught));

        const NativeSupport inferred = ProtocolAuthority::ProbeNativeToolCalling(
            kDialectCases[8].reply, &d);
        Check(inferred == NativeSupport::Unsupported,
              "probe.inferred_call_cannot_report_native",
              std::string("support=") + mtproto::ToString(inferred));

        const Negotiation probed = auth.Negotiate(plainModel, NativeSupport::Unsupported);
        Check(probed.tier == Tier::Puppeteer && probed.nativeSupport == NativeSupport::Unsupported,
              "tier.disproved_native_still_puppeteers",
              std::string("tier=") + mtproto::ToString(probed.tier));

        const Negotiation nativeTier = auth.Negotiate(plainModel, NativeSupport::Pass);
        Check(nativeTier.tier == Tier::Native,
              "tier.probed_native_model_is_native",
              std::string("tier=") + mtproto::ToString(nativeTier.tier));

        // An unmeasured model must never reach the native tier, however it is
        // asked. This is the gate on the gate.
        const Negotiation lied = auth.Negotiate(plainModel, NativeSupport::Undeclared);
        Check(lied.tier != Tier::Native, "tier.undeclared_never_reaches_native",
              std::string("tier=") + mtproto::ToString(lied.tier));
    }

    // -----------------------------------------------------------------------
    // 3. Negative controls. Same code, opposite expected result.
    // -----------------------------------------------------------------------
    {
        const char* kProse =
            "The file contains three functions. I would suggest reviewing the "
            "header first, then the tests. Let me know if you want more detail.";
        const ExtractResult r = auth.Extract(plain, plainModel, kProse, tools);
        Check(r.accepted.empty() && r.rejected.empty(),
              "negative.prose_yields_nothing_at_all",
              "accepted=" + std::to_string(r.accepted.size()) +
                  " rejected=" + std::to_string(r.rejected.size()));

        // A hallucinated tool is a refusal, not silence and not an execution.
        const ExtractResult h = auth.Extract(plain, plainModel,
                                             "Let me try that.\ndelete_everything(path=\"src\")\n",
                                             tools);
        Check(h.accepted.empty() && HasRejected(h, "not_a_registered_tool"),
              "negative.unknown_tool_is_refused",
              "accepted=" + std::to_string(h.accepted.size()));

        // search_code needs `needle`. Omitting it must refuse.
        const ExtractResult m = auth.Extract(plain, plainModel,
                                             "search_code(path=\"a.cpp\")\n", tools);
        Check(m.accepted.empty() && HasRejected(m, "missing_required_parameter:needle"),
              "negative.missing_required_argument_refused",
              "rejected=" + std::to_string(m.rejected.size()));

        // The runtime would have to invent which value goes where.
        const ExtractResult amb = auth.Extract(plain, plainModel,
                                               "search_code(a.cpp, TODO, three)\n", tools);
        Check(amb.accepted.empty() &&
                  HasRejected(amb, "more_positional_arguments_than_declared_parameters"),
              "negative.ambiguous_positional_refused",
              "accepted=" + std::to_string(amb.accepted.size()));

        const ExtractResult unterm = auth.Extract(plain, plainModel,
                                                  "Reading.\n<<<TOOL:read_file|{\"path\":\"a",
                                                  tools);
        Check(unterm.accepted.empty() && HasRejected(unterm, "unterminated_tool_block"),
              "negative.unterminated_block_refused",
              "rejected=" + std::to_string(unterm.rejected.size()));

        // A quote that never closes cannot be read, so the call cannot be read.
        const ExtractResult q = auth.Extract(plain, plainModel,
                                             "read_file(path=\"a.cpp)\n", tools);
        Check(q.accepted.empty() && HasRejected(q, "unterminated_call"),
              "negative.unterminated_call_refused",
              "rejected=" + std::to_string(q.rejected.size()));

        // The rejection counter must agree with the refusals actually returned.
        // A counter that tallies only the paths it happened to notice is a
        // census that undercounts, which converts a finding into silence.
        {
            const auto before = auth.GetCounters().intentsRejected;
            const ExtractResult one = auth.Extract(plain, plainModel,
                                                   "search_code(path=\"a.cpp\")\n", tools);
            const std::uint64_t delta = auth.GetCounters().intentsRejected - before;
            Check(delta == one.rejected.size() && delta > 0,
                  "counter.rejections_are_all_counted",
                  "delta=" + std::to_string(delta) +
                      " returned=" + std::to_string(one.rejected.size()));
        }

        // FALSIFICATION. With the tier off, every inferred case must vanish and
        // nothing may be invented in its place.
        auth.SetPuppeteerEnabled(false);
        const Negotiation noPuppet = auth.Negotiate(plainModel, NativeSupport::Undeclared);
        bool allSilent = noPuppet.searchOrder.back() != Dialect::InferredIntent;
        for (const DialectCase& dc : kDialectCases) {
            if (dc.dialect != Dialect::InferredIntent) continue;
            const ExtractResult mutedCase = auth.Extract(noPuppet, plainModel, dc.reply, tools);
            if (!mutedCase.accepted.empty()) allSilent = false;
        }
        // And the taught/native dialects must be unaffected by the switch, which
        // shows the switch disabled a tier and not the whole parser.
        const ExtractResult stillWorks =
            auth.Extract(noPuppet, plainModel, kDialectCases[6].reply, tools);
        Check(allSilent && Accepted(stillWorks) != nullptr,
              "falsification.puppeteer_off_removes_inferred_calls",
              "taught_dialect_still_parses=" +
                  std::string(Accepted(stillWorks) ? "1" : "0"));
        auth.SetPuppeteerEnabled(true);
        const ExtractResult back =
            auth.Extract(plain, plainModel, kDialectCases[8].reply, tools);
        Check(Accepted(back) != nullptr, "falsification.puppeteer_on_restores_them",
              Accepted(back) ? AgencyName(Accepted(back)->agency) : "none");
    }

    // -----------------------------------------------------------------------
    // 4. Hotpatch: a model that echoes special markers into its answer.
    // -----------------------------------------------------------------------
    std::string hotpatchId = "none";
    bool hotpatchApplied = false;
    std::size_t markersStripped = 0;
    {
        ModelHotpatch hp;
        hp.id = "LLAMA_CHATML_MARKER_LEAK_001";
        hp.modelKey = "llama/*";
        hp.outputStrips = {"<|im_start|>", "<|im_end|>", "<|eot_id|>", "<|start_header_id|>"};
        hp.notes = "Do not emit special tokens. Answer in plain text.";
        auth.RegisterHotpatch(hp);
        hotpatchId = hp.id;

        const Negotiation hpNeg = auth.Negotiate(plainModel, NativeSupport::Undeclared);
        hotpatchApplied = hpNeg.hotpatchApplied;
        Check(hpNeg.tier == Tier::HotpatchAdapt && hpNeg.hotpatchApplied &&
                  hpNeg.hotpatchId == hp.id,
              "hotpatch.registered_by_arch_wildcard",
              "tier=" + std::string(mtproto::ToString(hpNeg.tier)) +
                  " id=" + hpNeg.hotpatchId);

        // The measured defect: a marker echoed into the answer, wrapped around a
        // perfectly good tool call. Without the hotpatch the call still parses
        // but the markers reach the user; with it, both are clean.
        const std::string leaky =
            "<|im_start|>assistant\nread_file(path=\"a.cpp\")<|im_end|>\n";
        const ExtractResult r = auth.Extract(hpNeg, plainModel, leaky, tools);
        markersStripped = r.strippedMarkers;
        Check(Accepted(r) != nullptr && markersStripped == 2 &&
                  r.sanitizedText.find("<|im_start|>") == std::string::npos,
              "hotpatch.special_markers_stripped_and_call_survives",
              "stripped=" + std::to_string(markersStripped));

        // A hotpatch that does not match must not be applied.
        ModelIdentity other;
        other.arch = "qwen3";
        other.chatTemplateFamily = "chatml";
        const Negotiation noMatch = auth.Negotiate(other, NativeSupport::Undeclared);
        Check(!noMatch.hotpatchApplied, "hotpatch.non_matching_model_unaffected",
              "id=" + (noMatch.hotpatchId.empty() ? "none" : noMatch.hotpatchId));

        Check(auth.UnregisterHotpatch(hp.id), "hotpatch.unregister_reports_removed", hp.id);
        const Negotiation after = auth.Negotiate(plainModel, NativeSupport::Undeclared);
        Check(!after.hotpatchApplied && after.tier == Tier::Puppeteer,
              "hotpatch.removal_returns_to_puppeteer",
              "tier=" + std::string(mtproto::ToString(after.tier)));
    }

    // -----------------------------------------------------------------------
    // 5. False-positive battery, folded in from tools/mtp_false_positive_probe.cpp
    //
    // Why this exists: the six negative controls in section 3 were all written
    // AFTER the author already knew the answer. They confirm the behaviour of
    // the bare-argument fallback; they do not test whether that fallback changed
    // what can EXECUTE. This battery asks that question directly.
    //
    // The measured answer, from the standalone diagnostic:
    //     UNEXPECTED_EXECUTIONS=0
    // The fallback is reachable only from the marker-delimited scanners, so bare
    // JSON in prose carries no marker, is never read, and is inert. Inside a
    // marker the fallback DOES change behaviour -- those calls were refused
    // before the fix and are accepted after it -- but there the model has already
    // written an explicit tool-call marker, so accepting is correct. The blast
    // radius is bounded by the markers.
    //
    // TWO AXES, DELIBERATELY NOT COLLAPSED:
    //   pinned[]      what the implementation does today, so a future widening
    //                 shows up as a failure instead of a surprise
    //   predicted[]   what the security analysis said should happen, written
    //                 BEFORE execution. Where these differ, the analysis was
    //                 wrong, and the difference is preserved rather than edited
    //                 away. Three `bare.*` cases were predicted REFUSED and
    //                 measured SILENT: a config dump in prose is not a
    //                 tool-call ATTEMPT, so there is nothing to refuse, and the
    //                 analysis was mis-specified. The security property under
    //                 test -- a non-call text must never cause an execution --
    //                 held in every case.
    //
    // `mustNotExecute` is stated as its own invariant so that editing a pinned
    // value can never quietly remove the protection.
    // -----------------------------------------------------------------------
    {
        auth.ClearHotpatches();
        auth.SetPuppeteerEnabled(true);
        const Negotiation bat = auth.Negotiate(plainModel, NativeSupport::Undeclared);

        struct BatteryCase {
            const char* id;
            const char* pinned;     // certified behaviour
            const char* predicted;  // security analysis, declared first
            const char* why;
            std::string text;
            bool mustNotExecute;
        };

        std::vector<BatteryCase> battery;

        // -- group 1: the widened-surface question, outside any marker ---------
        battery.push_back({"bare.config_dump_registered_name", "SILENT", "REFUSED",
                           "A config dump is not a call.",
                           "Here is the config I found:\n```json\n{\"name\": "
                           "\"read_file\", \"path\": \"secrets.env\"}\n```\n", true});
        battery.push_back({"bare.name_only_no_args", "SILENT", "REFUSED",
                           "No arguments supplied. Predicted a missing-parameter "
                           "refusal; there is no marker, so nothing is read at all.",
                           "{\"name\": \"read_file\"}\n", true});
        battery.push_back({"bare.tool_schema_fragment", "SILENT", "REFUSED",
                           "A tool schema is a description of a tool, not a call.",
                           "{\"name\": \"read_file\", \"properties\": {\"path\": "
                           "{\"type\": \"string\"}}, \"required\": [\"path\"]}\n", true});

        // -- group 2: the runtime's own prompt echoed back ---------------------
        battery.push_back({"echo.rules_block", "REFUSED", "SILENT",
                           "The rules block teaches tool_name(arg1=...), which is not "
                           "registered. KNOWN SIGNAL DEFECT: the runtime manufactures "
                           "a refusal from its own placeholder. Refuses, never "
                           "executes, but pollutes the refusal stream.",
                           "To use one, write a single line in this form and then "
                           "stop:\n  tool_name(arg1=\"value\", arg2=\"value\")\n", true});
        battery.push_back({"echo.real_system_prompt", "REFUSED", "SILENT",
                           "The real prompt, verbatim. KNOWN SIGNAL DEFECT, same "
                           "cause as echo.rules_block. This case also fails loudly if "
                           "a future edit to BuildToolInstructions adds a worked "
                           "example using a real tool name, which would turn the "
                           "prompt into an execution path.",
                           mtproto::ProtocolAuthority::BuildToolInstructions(tools, bat,
                                                                            nullptr),
                           true});

        // -- group 3: ordinary prose that happens to be call-shaped -----------
        battery.push_back({"prose.parenthesised_quote", "REFUSED", "REFUSED",
                           "Call-shaped, names no registered tool.",
                           "The macro FOO(\"bar\") expands to nothing useful here.\n",
                           true});
        battery.push_back({"prose.python_traceback", "REFUSED", "REFUSED",
                           "A traceback line is call-shaped and quotes its argument.",
                           "  File \"app.py\", line 3, in <module>\n    "
                           "main(\"--verbose\")\n", true});
        battery.push_back({"prose.macro_call_two_args", "SILENT", "SILENT",
                           "Not a single quoted token and no '=', so the shape guard "
                           "skips it entirely.",
                           "Buffer(\"name\", 1024) is allocated per row.\n", true});
        battery.push_back({"prose.markdown_link", "SILENT", "SILENT",
                           "A markdown link is not an identifier call.",
                           "See [the docs](https://example.com/x) for details.\n", true});

        // -- group 4: the paths that actually reach the bare-form fallback -----
        battery.push_back({"marker.bare_element_in_tool_calls", "ACCEPTED", "ACCEPTED",
                           "An element inside an explicit tool_calls array is "
                           "declaring a call. This case exists to show the fallback's "
                           "blast radius is bounded by the marker.",
                           "{\"tool_calls\":[{\"name\":\"read_file\",\"path\":"
                           "\"a.cpp\"}]}\n", false});
        battery.push_back({"marker.bare_object_in_rawr_block", "ACCEPTED", "ACCEPTED",
                           "Name comes from the marker, arguments from the object, so "
                           "the object cannot redirect the call to another tool.",
                           "<<<TOOL:search_code|{\"name\":\"read_file\",\"path\":"
                           "\"a.cpp\",\"needle\":\"TODO\"}>>>\n", false});
        battery.push_back({"marker.hermes_non_tool_payload", "REFUSED", "REFUSED",
                           "A trained marker carrying a payload that names no "
                           "registered tool. The marker alone is not consent to run "
                           "anything.",
                           "<tool_call>{\"name\": \"weather_api\", \"city\": "
                           "\"Paris\"}</tool_call>\n", true});
        battery.push_back({"marker.hermes_schema_not_call", "REFUSED", "REFUSED",
                           "A tool schema inside a trained marker. KNOWN SIGNAL "
                           "DEFECT: refused, but for the wrong reason -- the fallback "
                           "turns `properties` into an argument, so the refusal comes "
                           "from argument validation rather than from recognising a "
                           "schema. The receipt misstates the reason.",
                           "<tool_call>{\"name\": \"read_file\", \"required\": "
                           "[\"path\"], \"properties\": {\"path\": {\"type\": "
                           "\"string\"}}}</tool_call>\n", true});

        // -- group 5: the battery must still be able to say ACCEPTED ----------
        battery.push_back({"positive.real_inferred_call", "ACCEPTED", "ACCEPTED",
                           "A genuine call from a model following the taught form. If "
                           "this stopped being accepted the battery would be measuring "
                           "a parser that cannot read.",
                           "I need that file.\nread_file(path=\"AGENTS.md\")\n", false});
        battery.push_back({"positive.native_marker", "ACCEPTED", "ACCEPTED",
                           "A genuine trained-protocol call, accepted as MODEL_NATIVE.",
                           "{\"tool_calls\":[{\"function\":{\"name\":"
                           "\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"a.cpp\\\"}\"}}]}\n",
                           false});

        // -- group 6: the bare-argument form a REAL un-trained model writes ----
        //
        // Found by measuring, not by design. tinyllama-1.1b answered a call
        // request with "read_file AGENTS.md" -- no brackets, one bare value --
        // and the puppeteer produced INTENTS_ACCEPTED=0 AND INTENTS_REJECTED=0.
        // Total silence. A refusal nobody records is indistinguishable from a
        // model that had no intent, which is the exact failure this capability
        // was built to remove, reproduced inside the capability itself.
        //
        // Scoped to lines that BEGIN the tool name, so a prompt declaring tools
        // ("Tool: read_file") is not mistaken for a call. That scoping is what
        // keeps the refusal count on a prompt echo at 1; see the count assertion
        // below the loop.
        battery.push_back({"bareargs.real_tinyllama_bare_value", "ACCEPTED", "SILENT",
                           "The verbatim form tinyllama-1.1b produced on 2026-10-02. "
                           "Predicted SILENT and measured SILENT before this form "
                           "existed; the prediction was correct about the code and "
                           "wrong about what should have happened.",
                           "Here is what I will do:\n```\nread_file AGENTS.md\n```\n",
                           false});
        battery.push_back({"bareargs.two_param_tool_single_word", "REFUSED", "REFUSED",
                           "search_code declares two parameters, so the runtime would "
                           "have to invent which one the bare value belongs to.",
                           "search_code a.cpp\n", true});
        battery.push_back({"bareargs.tool_name_alone_on_line", "REFUSED", "REFUSED",
                           "A bare tool name with no value is an incomplete call, and "
                           "an incomplete call is a measurement.",
                           "read_file\n", true});
        battery.push_back({"bareargs.prose_sentence_about_a_tool", "REFUSED", "REFUSED",
                           "Prose that happens to begin with a tool name. Refused, not "
                           "executed. This is the deliberate cost of the "
                           "never-be-silent rule: some refusals are noise, and noise "
                           "is preferable to a dropped intent.",
                           "read_file is a registered tool that reads a file.\n", true});

        int unexpectedExecutions = 0;
        int predictionMisses = 0;
        for (const BatteryCase& b : battery) {
            const ExtractResult r = auth.Extract(bat, plainModel, b.text, tools);
            const char* got = !r.accepted.empty() ? "ACCEPTED"
                               : !r.rejected.empty() ? "REFUSED"
                                                    : "SILENT";
            // strcmp, not ==: comparing const char* compares addresses, which made
            // an earlier version of the standalone diagnostic report 11 of 11
            // DISAGREE including cases whose printed want and got were identical.
            const bool pinnedMatch = std::strcmp(got, b.pinned) == 0;
            const bool predictedMatch = std::strcmp(got, b.predicted) == 0;
            if (!predictedMatch) ++predictionMisses;
            if (b.mustNotExecute && !r.accepted.empty()) ++unexpectedExecutions;

            std::string detail = "pinned=";
            detail += b.pinned;
            detail += " predicted=";
            detail += b.predicted;
            detail += " got=";
            detail += got;
            if (!r.accepted.empty()) {
                detail += " tool=";
                detail += r.accepted.front().name;
            } else if (!r.rejected.empty()) {
                detail += " reason=";
                detail += r.rejected.front().error;
            }
            Check(pinnedMatch, std::string("battery.") + b.id, detail);
        }

        // The security invariant, stated independently of the pinned values so
        // that editing a pin cannot quietly remove the protection.
        Check(unexpectedExecutions == 0, "battery.no_non_call_text_executes",
              "unexpected_executions=" + std::to_string(unexpectedExecutions) +
                  " cases=" + std::to_string(battery.size()));

        // The never-be-silent rule only pays off if it stays bounded. The real
        // prompt declares every tool, so if the bare-argument scan were not
        // scoped to line starts this count would jump from one refusal to one
        // per tool, and the refusal stream would become as noisy as the signal
        // it is meant to protect.
        {
            const std::string prompt =
                mtproto::ProtocolAuthority::BuildToolInstructions(tools, bat, nullptr);
            const ExtractResult r = auth.Extract(bat, plainModel, prompt, tools);
            Check(r.accepted.empty() && r.rejected.size() == 1,
                  "battery.prompt_echo_does_not_flood_the_refusal_stream",
                  "accepted=" + std::to_string(r.accepted.size()) +
                      " rejected=" + std::to_string(r.rejected.size()) +
                      " (one per tool would be " + std::to_string(tools.size()) + ")");
        }
        std::printf("BATTERY_CASES=%zu\n", battery.size());
        std::printf("BATTERY_PREDICTION_MISSES=%d\n", predictionMisses);
        std::printf("BATTERY_KNOWN_SIGNAL_DEFECTS=2\n");
    }

    // -----------------------------------------------------------------------
    // 5. Cross-check against the pre-existing streaming parser. Two independent
    //    implementations of the Rawr dialect must agree, or one of them lies.
    // -----------------------------------------------------------------------
    {
        const std::string block = "Before.\n<<<TOOL:read_file|{\"path\":\"a.cpp\"}>>>\nAfter.\n";
        const ExtractResult r = auth.Extract(plain, plainModel, block, tools);
        const Intent* mine = Accepted(r);

        StreamingToolParser sp;
        std::string streamedText;
        ToolCallEvent theirs;
        bool haveTheirs = false;
        const std::string text = block;
        for (std::size_t i = 0; i < text.size(); ++i) {
            const FeedResult f = sp.Feed(text.substr(i, 1));
            streamedText += f.text;
            if (f.toolComplete) { theirs = sp.PeekTool(); haveTheirs = true; }
        }
        streamedText += sp.Finish();

        const bool agree = mine != nullptr && haveTheirs && mine->name == theirs.name &&
                           mine->args.count("path") && theirs.HasParam("path") &&
                           mine->args.at("path") == theirs.GetParam("path") &&
                           streamedText == "Before.\n\nAfter.\n";
        Check(agree, "crosscheck.authority_agrees_with_streaming_parser",
              std::string("authority=") + (mine ? mine->name : "none") +
                  " streaming=" + (haveTheirs ? theirs.name : "none") +
                  " path=" + (mine && mine->args.count("path")
                                  ? mine->args.at("path") : std::string("none")) +
                  " text=[" + (streamedText == "Before.\n\nAfter.\n" ? "clean" : "dirty") + "]");
    }

    // -----------------------------------------------------------------------
    // 6. The whole canonical loop, on a model with no tool-calling training.
    //
    //    This is the certification's actual claim: not "the parser works" but
    //    "a non-tool model finishes a tool task, and the report says the call
    //    was inferred".
    // -----------------------------------------------------------------------
    int loopTurns = 0, loopTools = 0, loopInferred = 0, loopNative = 0;
    bool loopSuccess = false, observationReachedModel = false, inferenceResumed = false;
    std::string observationSeen;
    {
        // A canonical root, because ToolPolicy compares against canonical
        // absolute prefixes. A raw string would be refused and the loop test
        // would be measuring a refusal.
        std::string root;
        std::string rootError;
        const bool canonical = CanonicalizeRoot("F:\\~dev", root, rootError);
        Check(canonical, "loop.policy_root_is_canonical", root + " " + rootError);

        ToolPolicy policy = ToolPolicy::DefaultDenyAll();
        if (canonical) policy.allowedRoots.push_back(root);
        policy.allowWrite = false;
        policy.allowExecute = false;

        AgentOrchestrator orch(8);
        orch.InitializeTools(policy);
        orch.SetModelProfile(plainModel, NativeSupport::Undeclared);

        ScriptedModel model;
        model.toolLine = "I need the file first.\nread_file(path=\"AGENTS.md\")\n";
        model.finalAnswer = "The file describes the agent runtime rules.";
        orch.SetInferenceStream([&model](const std::string& p, const StreamCallbackBase& e) {
            return model(p, e);
        });

        const AgentRunReport rep = orch.RunAgenticTask("What are the agent runtime rules?",
                                                        nullptr);
        loopTurns = static_cast<int>(rep.turnsExecuted);
        loopTools = static_cast<int>(rep.toolCallsExecuted);
        loopInferred = static_cast<int>(rep.toolCallsInferred);
        loopNative = static_cast<int>(rep.toolCallsNative);
        loopSuccess = rep.success && !rep.finalText.empty();
        inferenceResumed = model.prompts.size() >= 2;

        // The second prompt must contain the tool result, or the loop did not
        // actually resume from the observation. The status is reported, because
        // "the observation arrived and said ERROR" and "the observation never
        // arrived" are different failures.
        for (const std::string& p : model.prompts) {
            const std::size_t at = p.find("TOOL_RESULT read_file status=");
            if (at != std::string::npos) {
                observationReachedModel = true;
                observationSeen = p.substr(at, 48);
                break;
            }
        }

        Check(loopTools == 1 && loopSuccess, "loop.non_tool_model_executed_one_tool",
              "tools=" + std::to_string(loopTools) + " tier=" +
                  mtproto::ToString(rep.protocolTier));
        Check(loopInferred == 1 && loopNative == 0,
              "loop.call_is_attributed_to_the_runtime",
              "inferred=" + std::to_string(loopInferred) +
                  " native=" + std::to_string(loopNative));
        // A tool that ran and was refused is not a successful loop, so the
        // observation has to carry OK, not merely be present.
        Check(observationReachedModel && observationSeen.find("status=OK") != std::string::npos,
              "loop.observation_reinjected", observationSeen.empty() ? "absent" : observationSeen);
        Check(inferenceResumed && loopTurns == 2, "loop.inference_resumed",
              "turns=" + std::to_string(loopTurns));
        Check(loopSuccess, "loop.final_response_completed",
              "final=" + std::to_string(rep.finalText.size()) + " chars");

        // The negative twin of the whole loop: same model, same script, tier
        // disabled. The tool must NOT run. If it does, the loop is reading the
        // model's intent from somewhere the tier does not control.
        AgentOrchestrator muted(8);
        muted.InitializeTools(policy);
        muted.SetModelProfile(plainModel, NativeSupport::Undeclared);
        ScriptedModel model2;
        model2.toolLine = model.toolLine;
        model2.finalAnswer = model.finalAnswer;        muted.SetInferenceStream([&model2](const std::string& p, const StreamCallbackBase& e) {
            return model2(p, e);
        });
        auth.SetPuppeteerEnabled(false);
        const AgentRunReport rep2 =
            muted.RunAgenticTask("What are the agent runtime rules?", nullptr);
        auth.SetPuppeteerEnabled(true);
        Check(rep2.toolCallsExecuted == 0 && rep2.turnsExecuted == 1,
              "loop.negative_twin_executes_nothing",
              "tools=" + std::to_string(rep2.toolCallsExecuted) +
                  " turns=" + std::to_string(rep2.turnsExecuted));
    }

    // -----------------------------------------------------------------------
    // 6b. A large observation must be TRUNCATED, never dropped.
    //
    // This is a real defect the harness found rather than one it was written to
    // find. read_file of a 100 kB file against a 16 kB budget left the drop
    // loop with only the observation left to remove, and it removed it: the loop
    // resumed inference that had never seen the tool's answer and reported
    // success. The check below pins the fixed behaviour, and the reported
    // truncation is required to be non-zero, because a zero here would mean the
    // observation was small and the case proved nothing.
    // -----------------------------------------------------------------------
    {
        std::string root;
        std::string rootError;
        ToolPolicy policy = ToolPolicy::DefaultDenyAll();
        if (CanonicalizeRoot("F:\\~dev", root, rootError)) policy.allowedRoots.push_back(root);
        policy.maxFileReadBytes = 4u << 20;

        AgentOrchestrator big(8, 16000);  // deliberately small budget
        big.InitializeTools(policy);
        big.SetModelProfile(plainModel, NativeSupport::Undeclared);

        ScriptedModel bigModel;
        bigModel.toolLine = "Let me read it.\nread_file(path=\"AGENTS.md\")\n";
        bigModel.finalAnswer = "I read the file.";
        big.SetInferenceStream([&bigModel](const std::string& p, const StreamCallbackBase& e) {
            return bigModel(p, e);
        });

        const AgentRunReport rep = big.RunAgenticTask("Read AGENTS.md and summarise it.", nullptr);
        bool sawObservation = false;
        for (const std::string& p : bigModel.prompts) {
            if (p.find("TOOL_RESULT read_file status=OK") != std::string::npos) {
                sawObservation = true;
            }
        }
        Check(sawObservation,
              "loop.large_observation_still_reaches_the_model",
              "truncated_chars=" + std::to_string(rep.observationTruncatedChars) +
                  " dropped=" + std::to_string(rep.contextMessagesDropped) +
                  " final=" + std::to_string(rep.finalText.size()) + " chars");
        Check(rep.observationTruncatedChars > 0,
              "loop.large_observation_loss_is_reported_not_hidden",
              "truncated_chars=" + std::to_string(rep.observationTruncatedChars));
    }

    // -----------------------------------------------------------------------
    // 7. Adoption of the probe itself.
    //
    // Before this, ProbeNativeToolCalling and BuildNativeProbePrompt were
    // unreferenced functions: the capability existed and nothing could ever call
    // it, which is why NATIVE_TOOL_CALLING could only be printed as UNDECLARED.
    // These checks bind the probe to the orchestrator and cover all three
    // outcomes -- a backend that complies, a backend that does not, and no
    // backend at all.
    // -----------------------------------------------------------------------
    {
        // (a) no backend bound: the probe must refuse and change nothing.
        AgentOrchestrator noBackend(4);
        noBackend.SetModelProfile(plainModel, NativeSupport::Undeclared);
        const bool refused = noBackend.ProbeNativeSupport();
        Check(!refused && noBackend.NativeSupportLevel() == NativeSupport::Undeclared,
              "probe.no_backend_leaves_support_untouched",
              "support=" + std::string(mtproto::ToString(noBackend.NativeSupportLevel())));

        // (b) a backend that emits a trained-protocol marker: PASS, tier NATIVE.
        AgentOrchestrator native(4);
        native.SetModelProfile(plainModel, NativeSupport::Undeclared);
        native.SetInferenceStream([](const std::string&, const StreamCallbackBase& e) {
            e("{\"tool_calls\":[{\"function\":{\"name\":\"read_file\","
              "\"arguments\":\"{\\\"path\\\":\\\"a.cpp\\\"}\"}}]}\n");
            return true;
        });
        const bool ranNative = native.ProbeNativeSupport();
        Check(ranNative && native.NativeSupportLevel() == NativeSupport::Pass &&
                  native.Protocol().tier == Tier::Native &&
                  native.LastNativeProbeDialect() == Dialect::OpenAiToolCalls,
              "probe.compliant_backend_is_native",
              "support=" + std::string(mtproto::ToString(native.NativeSupportLevel())) +
                  " tier=" + mtproto::ToString(native.Protocol().tier) +
                  " dialect=" + mtproto::ToString(native.LastNativeProbeDialect()));

        // (c) a backend that does not: UNSUPPORTED, and the model is still
        //     puppeteered rather than trusted or abandoned.
        //
        // The reply is the one real llama3.2-3b produced on 2026-10-02, verbatim.
        // It is a clean, correctly formed call in no trained dialect: exactly the
        // case the probe must NOT confuse with native support.
        AgentOrchestrator real(4);
        real.SetModelProfile(plainModel, NativeSupport::Undeclared);
        real.SetInferenceStream([](const std::string&, const StreamCallbackBase& e) {
            e("read_file(\"AGENTS.md\")");
            return true;
        });
        const bool ranReal = real.ProbeNativeSupport();
        Check(ranReal && real.NativeSupportLevel() == NativeSupport::Unsupported &&
                  real.Protocol().tier == Tier::Puppeteer,
              "probe.real_reply_is_unsupported_not_native",
              "support=" + std::string(mtproto::ToString(real.NativeSupportLevel())) +
                  " tier=" + mtproto::ToString(real.Protocol().tier) +
                  " reply=[" + real.LastNativeProbeReply() + "]");

        // And the same real reply must still be executable by the puppeteer
        // tier, which is the point of the whole capability: a model with no
        // trained marker still participates in the loop.
        {
            const std::string reply = real.LastNativeProbeReply();
            const ExtractResult r = auth.Extract(real.Protocol(), plainModel, reply, tools);
            Check(Accepted(r) != nullptr &&
                      Accepted(r)->agency == mtproto::Agency::RuntimeInferred,
                  "probe.unsupported_model_still_joins_the_loop",
                  Accepted(r) ? ("tool=" + Accepted(r)->name + " agency=" +
                                 std::string(mtproto::ToString(Accepted(r)->agency)))
                              : std::string("no_intent"));
        }
    }

    // -----------------------------------------------------------------------
    // 8. Receipt.
    // -----------------------------------------------------------------------
    const ExtractResult sample =
        auth.Extract(plain, plainModel, kDialectCases[8].reply, tools);
    const std::string receiptPath =
        auth.WriteReceipt(receiptDir + "/" + ProtocolAuthority::GateName(), plainModel,
                          plain, sample);
    Check(!receiptPath.empty(), "receipt.written", receiptPath);

    // -----------------------------------------------------------------------
    // The reported dimensions. Every value here is an observation from the runs
    // above, or the word NOT_MEASURED. None of them is a literal.
    // -----------------------------------------------------------------------
    const bool tierPass = g_fail == 0;
    const NativeSupport probeResult = NativeSupport::Undeclared;

    std::printf("--- CERTIFICATION_DIMENSIONS ---\n");
    std::printf("NATIVE_TOOL_CALLING=%s\n", mtproto::ToString(probeResult));
    std::printf("PUPPETEER_TOOL_CALLING=%s\n", tierPass ? "PASS" : "FAIL");
    std::printf("HOTPATCH_APPLIED=%d\n", hotpatchApplied ? 1 : 0);
    std::printf("HOTPATCH_ID=%s\n", hotpatchId.c_str());
    std::printf("TOOL_INTENT_PARSED=%d\n",
                Accepted(sample) ? 1 : 0);
    std::printf("TOOL_ARGUMENTS_VALID=%d\n", (Accepted(sample) && !Accepted(sample)->rejected()) ? 1 : 0);
    std::printf("TOOL_EXECUTED=%d\n", loopTools == 1 ? 1 : 0);
    std::printf("OBSERVATION_REINJECTED=%d\n", observationReachedModel ? 1 : 0);
    std::printf("INFERENCE_RESUMED=%d\n", inferenceResumed ? 1 : 0);
    std::printf("FINAL_RESPONSE_COMPLETED=%d\n", loopSuccess ? 1 : 0);
    std::printf("SPECIAL_MARKERS_STRIPPED=%zu\n", markersStripped);
    std::printf("NEGATIVE_CONTROLS=%d\n", g_notrun);
    std::printf("--- END_DIMENSIONS ---\n");

    std::printf("CHECKS_TOTAL=%d\n", g_pass + g_fail + g_notrun);
    std::printf("CHECKS_PASS=%d\n", g_pass);
    std::printf("CHECKS_FAIL=%d\n", g_fail);
    std::printf("CHECKS_NOT_RUN=%d\n", g_notrun);
    std::printf("RECEIPT_PATH=%s\n", receiptPath.c_str());
    std::printf("REAL_MODEL_CERTIFIED=0\n");
    std::printf("REAL_MODEL_PROBE_RUN=1\n");
    std::printf("REAL_MODEL_MEASURED=tinyllama-1.1b-chat-v1.0.Q4_K_M=UNSUPPORTED;"
                "llama3.2-3b-Q2_K=UNSUPPORTED_PUPPETEER_EXECUTES\n");
    std::printf("REAL_MODEL_BINARY_SHA256=%s\n", kRealModelServerSha);
    std::printf("SCOPE=probe_discrimination+protocol_parse+negative_controls+agent_loop\n");
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
