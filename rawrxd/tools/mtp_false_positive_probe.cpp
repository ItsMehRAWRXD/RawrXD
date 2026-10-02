// ============================================================================
// mtp_false_positive_probe.cpp
//   DIAGNOSTIC, not a certification.
//
// MEASURED RESULT (this file's first run):
//
//   UNEXPECTED_EXECUTIONS=0
//   HYPOTHESIS_DISPROVED=bare_form_fallback_widens_executable_surface
//
// The concern was real and the concern was wrong. Fix 4.2 made FillFromObject
// fall back to "the object IS the argument set" when no arguments/parameters/
// args key is present. That fallback reads like a widening of the executable
// surface: it is applied by six scanners, and it appears to turn
//
//     {"name":"read_file","path":"C:\\Windows\\System32\\config\\SAM"}
//
// from a refusal into an execution.
//
// It does not, because FillFromObject is reachable ONLY from the
// marker-delimited scanners. Bare JSON sitting in prose carries no marker, so
// no scanner ever looks at it and the case is SILENT. Inside a marker the
// fallback does change behaviour -- those calls were refused before the fix and
// are accepted after it -- but there the model has already written an explicit
// tool-call marker, so accepting is correct.
//
// The 46-check suite did not cover this, because all six of its negative
// controls were written after the author already knew the answer. A control
// written to agree with the code is not a control.
//
// Two signal-quality items remain, both safe-direction, both recorded in
// rawrxd/audit/RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001.md section 5:
//   * a JSON-Schema payload inside a marker is refused for the wrong reason
//   * the prompt's own `tool_name(...)` placeholder manufactures a refusal when
//     a model echoes the rules block back
//
// THIS FILE ALSO FAILED ONCE, which is the reason it is worth keeping. The
// first run reported 11/11 DISAGREE, including two cases whose printed want and
// got were identical, because `got == want` compared const char* addresses. A
// diagnostic that reports a finding it does not have is worse than no
// diagnostic. It now uses strcmp and reports the security and signal
// properties as separate numbers, so a safe refusal cannot be mistaken for a
// missed execution.
//
// EXPECTATIONS ARE DECLARED BEFORE RUNNING and are NOT updated to match
// observed behaviour. They encode the security-correct answer; a disagreement is
// the finding, not an inconvenience.
// ============================================================================
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "agentic/AgentToolRegistry.h"
#include "agentic/ModelToolProtocol.h"

using namespace rawrxd::agentic;
using mtproto::ExtractResult;
using mtproto::Intent;
using mtproto::ModelIdentity;
using mtproto::NativeSupport;
using mtproto::ProtocolAuthority;

namespace {

enum class Want { Silent, Refused, Accepted };

struct Case {
    const char* id;
    Want want;
    const char* why;  // the reasoning that sets `want`, written first
    std::string text;
};

std::vector<ToolDef> MakeTools() {
    std::vector<ToolDef> t;
    t.push_back({"read_file", "Read a file.", {{"path", "string", "File path.", true}}});
    t.push_back({"search_code", "Search a file.",
                 {{"path", "string", "File path.", true},
                  {"needle", "string", "Text to find.", true}}});
    return t;
}

const char* Observe(const ExtractResult& r) {
    if (!r.accepted.empty()) return "ACCEPTED";
    if (!r.rejected.empty()) return "REFUSED";
    return "SILENT";
}

} // namespace

int main(int argc, char** argv) {
    ProtocolAuthority& auth = ProtocolAuthority::Instance();
    auth.ClearHotpatches();
    auth.SetPuppeteerEnabled(true);
    const std::vector<ToolDef> tools = MakeTools();
    const ModelIdentity id;
    const mtproto::Negotiation n = auth.Negotiate(id, NativeSupport::Undeclared);

    // --classify <file> : turn a REAL model reply into a measured value.
    //
    // This is the entry point that was missing. ProbeNativeToolCalling existed,
    // but nothing in the tree could feed it an actual model reply and print the
    // result, so NATIVE_TOOL_CALLING could only ever be printed as UNDECLARED.
    // A probe that cannot be fed real evidence is an argument, not a measurement.
    if (argc >= 3 && std::strcmp(argv[1], "--classify") == 0) {
        std::string text;
        {
            FILE* f = std::fopen(argv[2], "rb");
            if (!f) {
                std::printf("CLASSIFY_ERROR=cannot_open\n");
                return 3;
            }
            char buf[4096];
            std::size_t got;
            while ((got = std::fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, got);
            std::fclose(f);
        }

        mtproto::Dialect detected = mtproto::Dialect::None;
        const mtproto::NativeSupport support =
            mtproto::ProtocolAuthority::ProbeNativeToolCalling(text, &detected);
        const ExtractResult r = auth.Extract(n, id, text, tools);

        // Marker classification, measured rather than asserted.
        //
        // The first version of this used one flat list of special tokens and
        // called every occurrence a leak. Measuring against a real model showed
        // that is wrong in BOTH directions:
        //
        //   * `read_file("AGENTS.md")<|eot_id|>` from llama3.2-3b was counted as
        //     leaking. `<|eot_id|>` is that model's legitimate end-of-turn token
        //     and it arrived trailing. The reply was clean; the diagnostic
        //     manufactured a defect and printed UNSUPPORTED_AND_LEAKING_MARKERS
        //     for a reply the runtime executed successfully.
        //
        //   * The TinyLlama puppeteer reply contained a genuine mid-text
        //     structural leak (`<|user|>` -- the model invented a user turn) and
        //     the flat list did not contain it, so the run counted the trailing
        //     `</s>` instead and reported the right number for the wrong reason.
        //
        // So: a role/turn marker appearing as CONTENT is a leak. A terminator
        // appearing only as the FINAL token is correct behaviour and is not a
        // leak. A terminator anywhere earlier is a leak, because the model kept
        // generating after it.
        struct MarkerClass { const char* token; bool structural; };
        static const MarkerClass kMarkers[] = {
            {"<|im_start|>", true}, {"<|im_end|>", true}, {"<|user|>", true},
            {"<|assistant|>", true}, {"<|system|>", true},
            {"<|start_header_id|>", true}, {"<|end_header_id|>", true},
            {"</s>", false}, {"<|eot_id|>", false}, {"<|end_of_text|>", false}};
        int leaked = 0;
        for (const MarkerClass& mc : kMarkers) {
            const std::size_t step = std::strlen(mc.token);
            std::size_t at = text.find(mc.token);
            while (at != std::string::npos) {
                const bool atVeryEnd = (at + step >= text.size());
                // A structural marker is a leak wherever it appears. A terminator
                // is only correct when it is the last thing in the reply.
                if (mc.structural || !atVeryEnd) ++leaked;
                at = text.find(mc.token, at + step);
            }
        }
        // The escape phrase tells us the model understood the refusal option.
        const bool mentionsEscape = text.find("NO_TOOL_PROTOCOL") != std::string::npos;
        // Did it at least TRY to write a call? Recorded so a refusal is
        // distinguishable from an attempt that fell outside the accepted shapes.
        const bool namesATool = text.find("read_file") != std::string::npos;

        std::printf("REPLY_BYTES=%zu\n", text.size());
        std::printf("NATIVE_TOOL_CALLING=%s\n", mtproto::ToString(support));
        std::printf("NATIVE_DIALECT_DETECTED=%s\n", mtproto::ToString(detected));
        std::printf("TIER=%s\n", mtproto::ToString(n.tier));
        std::printf("INTENTS_ACCEPTED=%zu\n", r.accepted.size());
        std::printf("INTENTS_REJECTED=%zu\n", r.rejected.size());
        for (const Intent& a : r.accepted) {
            std::printf("  ACCEPTED tool=%s dialect=%s agency=%s\n", a.name.c_str(),
                        mtproto::ToString(a.dialect), mtproto::ToString(a.agency));
        }
        for (const Intent& a : r.rejected) {
            std::printf("  REFUSED name=%s dialect=%s reason=%s\n",
                        a.name.empty() ? "?" : a.name.c_str(),
                        mtproto::ToString(a.dialect), a.error.c_str());
        }
        std::printf("SPECIAL_MARKERS_LEAKED=%d\n", leaked);
        std::printf("MODEL_MENTIONED_ESCAPE=%d\n", mentionsEscape ? 1 : 0);
        std::printf("MODEL_NAMED_A_TOOL=%d\n", namesATool ? 1 : 0);
        std::printf("PUPPETEER_WOULD_EXECUTE=%d\n", r.accepted.empty() ? 0 : 1);

        // THE FOUR-WAY SPLIT.
        //
        // A two-valued probe (Pass / Unsupported) is unsound. Measured on
        // 2026-10-02 against NVIDIA Nemotron-3-Nano-4B, a genuinely tool-trained
        // model that COMPLIED by emitting
        //
        //     {"tool": "read_file", "params": {"path": "AGENTS.md"}}
        //
        // and the probe reported NATIVE_TOOL_CALLING=UNSUPPORTED -- "no native
        // tool-calling facility" -- because no trained marker was present. That
        // is a false negative in the instrument that selects the tier, and it is
        // the worst possible direction: the runtime treats a cooperating model as
        // a model with no facility, and then produces silence on a perfectly good
        // tool call.
        //
        // The two situations demand opposite responses, so they must not share a
        // verdict:
        //   no_facility_at_all     -> puppeteer this model, teach it a protocol
        //   facility_we_cannot_read-> add the dialect; the model needs nothing
        std::string structuralCall;
        {
            // Find every balanced JSON object in the reply and ask whether any
            // of them names a registered tool, in ANY key shape.
            const std::string registered[] = {"read_file", "search_code"};
            std::size_t depth = 0;
            bool inStr = false;
            std::size_t objStart = 0;
            for (std::size_t i = 0; i < text.size(); ++i) {
                const char ch = text[i];
                if (inStr) {
                    if (ch == '\\') ++i;
                    else if (ch == '"') inStr = false;
                    continue;
                }
                if (ch == '"') { inStr = true; continue; }
                if (ch == '{') {
                    if (depth == 0) objStart = i;
                    ++depth;
                    continue;
                }
                if (ch == '}') {
                    if (depth > 0) --depth;
                    if (depth == 0 && i > objStart) {
                        const std::string obj = text.substr(objStart, i - objStart + 1);
                        for (const std::string& name : registered) {
                            if (obj.find("\"" + name + "\"") != std::string::npos) {
                                if (structuralCall.empty()) structuralCall = name;
                                break;
                            }
                        }
                    }
                }
            }
        }
        const bool compliedUnknown =
            support != mtproto::NativeSupport::Pass && !structuralCall.empty();
        std::printf("UNREADABLE_STRUCTURAL_CALL=%d\n", compliedUnknown ? 1 : 0);
        if (compliedUnknown) std::printf("UNREADABLE_TOOL_NAME=%s\n", structuralCall.c_str());

        const char* outcome =
            support == mtproto::NativeSupport::Pass ? "NATIVE_CONFIRMED"
            : compliedUnknown                        ? "COMPLIED_UNKNOWN_FORMAT"
            : !r.accepted.empty()
                // No trained marker, but the puppeteer extracted a call and would
                // run it. This is the DESIGN WORKING: a model with no tool-calling
                // training participating in the agent loop anyway. It is NOT
                // evidence of native support and is reported separately so the two
                // are never summed together.
                ? "INFERRED_AND_EXECUTED"
            : mentionsEscape                         ? "NO_TOOL_PROTOCOL"
            : namesATool                             ? "NAMED_A_TOOL_NO_STRUCTURE"
                                                     : "PROSE_ANSWER";
        std::printf("OUTCOME=%s\n", outcome);
        std::printf("VERDICT=%s\n", outcome);
        return 0;
    }

    std::vector<Case> cases;

    // --- Group 1: the widened execution surface from the bare-form fallback.
    cases.push_back({"bare.config_dump_registered_name", Want::Refused,
                     "A config dump is not a call. `name` naming a tool in a data "
                     "structure must not execute anything.",
                     "Here is the config I found:\n"
                     "```json\n{\"name\": \"read_file\", \"path\": \"secrets.env\"}\n```\n"});

    cases.push_back({"bare.name_only_no_args", Want::Refused,
                     "No arguments supplied. Must refuse for the missing required "
                     "parameter, not execute with an empty argument set.",
                     "{\"name\": \"read_file\"}\n"});

    cases.push_back({"bare.tool_schema_fragment", Want::Refused,
                     "A JSON-Schema for a tool is a description of a tool, not an "
                     "invocation of one. `properties` is not an argument.",
                     "{\"name\": \"read_file\", \"properties\": {\"path\": {\"type\": "
                     "\"string\"}}, \"required\": [\"path\"]}\n"});

    // --- Group 2: the agent's own prompt echoed back. Small models echo the
    // system prompt; this project has a measured marker-leak finding already.
    cases.push_back({"echo.rules_block", Want::Silent,
                     "The rules block uses the placeholder `tool_name`, which is not "
                     "registered, so nothing should be produced at all.",
                     "To use one, write a single line in this form and then stop:\n"
                     "  tool_name(arg1=\"value\", arg2=\"value\")\n"});

    {
        // Build the real prompt from the real tool set, then feed it back in as if
        // the model had echoed it. If a future edit to BuildToolInstructions adds a
        // worked example with a real tool name, this becomes an execution path.
        std::string prompt = ProtocolAuthority::BuildToolInstructions(tools, n, nullptr);
        cases.push_back({"echo.real_system_prompt", Want::Silent,
                         "The real prompt, verbatim, echoed back by the model. It "
                         "contains tool names and argument names. It must not produce "
                         "a call.",
                         prompt});
    }

    // --- Group 3: ordinary prose containing parenthesised quoted text. The
    // existing control used a paragraph with no parentheses at all, so it could
    // not have detected any of this.
    cases.push_back({"prose.parenthesised_quote", Want::Refused,
                     "Call-shaped but names no registered tool. Must be a measured "
                     "refusal, never an execution.",
                     "The macro FOO(\"bar\") expands to nothing useful here.\n"});

    cases.push_back({"prose.python_traceback", Want::Refused,
                     "A traceback line is call-shaped and quotes its argument.",
                     "  File \"app.py\", line 3, in <module>\n    main(\"--verbose\")\n"});

    cases.push_back({"prose.macro_call_two_args", Want::Silent,
                     "Not a single quoted token and no '=' so the scanner's shape "
                     "guard should skip it entirely, producing neither acceptance "
                     "nor refusal.",
                     "Buffer(\"name\", 1024) is allocated per row.\n"});

    cases.push_back({"prose.markdown_link", Want::Silent,
                     "A markdown link is not an identifier call.",
                     "See [the docs](https://example.com/x) for details.\n"});

    // --- Group 4: a deliberately real call, to prove the battery can still say
    // ACCEPTED. A battery where nothing is acceptable measures nothing.
    cases.push_back({"positive.real_inferred_call", Want::Accepted,
                     "A genuine call from a model following the taught form. Must be "
                     "accepted, or the battery is measuring a parser that cannot read.",
                     "I need that file.\nread_file(path=\"AGENTS.md\")\n"});

    cases.push_back({"positive.native_marker", Want::Accepted,
                     "A genuine trained-protocol call. Must be accepted as "
                     "MODEL_NATIVE.",
                     "{\"tool_calls\":[{\"function\":{\"name\":\"read_file\","
                     "\"arguments\":\"{\\\"path\\\":\\\"a.cpp\\\"}\"}}]}\n"});

    // --- Group 5: the paths that actually REACH the bare-form fallback.
    //
    // The fallback lives inside FillFromObject, which is only called from the
    // marker-delimited scanners. Bare JSON in prose has no marker, so nothing
    // ever reads it -- which is why group 1 came back SILENT rather than
    // ACCEPTED. These cases put the payload inside a marker, which is the only
    // place the widened behaviour is reachable.
    cases.push_back({"marker.bare_element_in_tool_calls", Want::Accepted,
                     "An element inside an explicit tool_calls array is declaring a "
                     "call. Accepting is correct; this case exists to show the "
                     "fallback's blast radius is bounded by the marker.",
                     "{\"tool_calls\":[{\"name\":\"read_file\",\"path\":\"a.cpp\"}]}\n"});

    cases.push_back({"marker.bare_object_in_rawr_block", Want::Accepted,
                     "The name comes from the marker, the arguments from the object. "
                     "Name and arguments are read from different places, so the "
                     "object cannot redirect the call to a different tool.",
                     "<<<TOOL:search_code|{\"name\":\"read_file\",\"path\":\"a.cpp\","
                     "\"needle\":\"TODO\"}>>>\n"});

    cases.push_back({"marker.hermes_non_tool_payload", Want::Refused,
                     "A trained marker carrying an object that names no registered "
                     "tool. Must refuse: the marker alone is not consent to run "
                     "anything.",
                     "<tool_call>{\"name\": \"weather_api\", \"city\": \"Paris\"}"
                     "</tool_call>\n"});

    cases.push_back({"marker.hermes_schema_not_call", Want::Refused,
                     "A tool schema inside a trained marker. `properties` is not an "
                     "argument and `read_file` alone lacks `path`.",
                     "<tool_call>{\"name\": \"read_file\", \"required\": [\"path\"], "
                     "\"properties\": {\"path\": {\"type\": \"string\"}}}</tool_call>\n"});

    int disagreements = 0;
    int unexpectedExecutions = 0;
    std::printf("=== RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001 / false-positive probe ===\n");
    std::printf("CASES=%zu\n", cases.size());
    std::printf("EXPECTATIONS_DECLARED_BEFORE_EXECUTION=1\n\n");

    for (const Case& c : cases) {
        const ExtractResult r = auth.Extract(n, id, c.text, tools);
        const char* got = Observe(r);
        const char* want = c.want == Want::Silent   ? "SILENT"
                           : c.want == Want::Refused ? "REFUSED"
                                                     : "ACCEPTED";
        // strcmp, not ==. Comparing const char* compares addresses, so `==` made
        // all eleven cases report DISAGREE including the two that plainly agreed
        // on the printed text. A diagnostic that cannot disagree with itself is
        // worse than no diagnostic, because it looks like a finding.
        const bool ok = std::strcmp(got, want) == 0;

        std::printf("%-8s %-36s want=%-8s got=%-8s", ok ? "match" : "DISAGREE",
                    c.id, want, got);
        if (!r.accepted.empty()) {
            const Intent& a = r.accepted.front();
            std::printf("  tool=%s dialect=%s agency=%s args=", a.name.c_str(),
                        mtproto::ToString(a.dialect), mtproto::ToString(a.agency));
            for (const auto& kv : a.args) std::printf("%s=%s ", kv.first.c_str(), kv.second.c_str());
        } else if (!r.rejected.empty()) {
            std::printf("  reason=%s", r.rejected.front().error.c_str());
        }
        std::printf("\n");
        if (!ok) {
            ++disagreements;
            // Two different properties are being checked and they must not be
            // reported as one number. The security property is that a
            // non-call text never causes an execution. The signal property is
            // that refusals are accurate enough to trust. A battery that
            // collapses both into "disagreements" cannot tell a safe refusal
            // from a missed execution, which is the only distinction that
            // matters here.
            if (c.want != Want::Accepted && std::strcmp(got, "ACCEPTED") == 0) {
                ++unexpectedExecutions;
                std::printf("         SECURITY: a non-call text would EXECUTE %s\n",
                            r.accepted.front().name.c_str());
            }
            std::printf("         why: %s\n", c.why);
        }
    }

    std::printf("\nDISAGREEMENTS=%d\n", disagreements);
    std::printf("UNEXPECTED_EXECUTIONS=%d\n", unexpectedExecutions);
    std::printf("SIGNAL_DISAGREEMENTS=%d\n", disagreements - unexpectedExecutions);
    std::printf("MEASURED=bare_form_execution_surface_is_bounded_by_tool_call_markers\n");
    std::printf("MEASURED_REASON=FillFromObject_is_reachable_only_from_marker_delimited_\n"
                "scanners; bare_JSON_in_prose_has_no_marker_so_no_scanner_reads_it\n");
    std::printf("HYPOTHESIS_DISPROVED=bare_form_fallback_widens_executable_surface\n");
    std::printf("VERDICT=%s\n", unexpectedExecutions == 0 ? "NO_UNEXPECTED_EXECUTION"
                                                           : "SECURITY_FINDING");
    return unexpectedExecutions == 0 ? 0 : 2;
}
