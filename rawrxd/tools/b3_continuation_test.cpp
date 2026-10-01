// B3 certification harness — RAWRXD_TOOL_AUTHORITY_SINGLE_001
//
// Proves three things about the same-session continuation path:
//
//   T1  canonical mode with an UNBOUND authority fails closed (no fallback)
//   T2  canonical mode with a BOUND authority executes the tool through
//       RawrXD::Agentic::AgentToolRegistry, is counted, and rejects add()
//   T3  a Session driven by injected ModelBindings emits a tool call, executes
//       it through the canonical authority, appends the observation, and
//       RESUMES THE SAME SESSION to a final answer
//
// T3 is the B3 gate. The model is injected because ModelBindings exists
// precisely so the runtime can be bound to a real backend; a harness-supplied
// binding exercises the same code path a loaded GGUF would, without requiring
// a multi-gigabyte model for a wiring test.

#include "../src/deep2/streaming/ContinuousExecution.hpp"
#include "../src/deep2/AgentToolAuthority.hpp"
#include "../src/deep2/AgentToolRegistry.hpp"

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>

using namespace rawrxd::continuous;
using RawrXD::Agentic::AgentToolRegistry;
using RawrXD::Agentic::ToolDescriptor;

static int g_fail = 0;
static void check(const char* name, bool ok, const std::string& ev) {
    if (!ok) ++g_fail;
    std::printf("%-46s %s   %s\n", name, ok ? "PASS" : "FAIL", ev.c_str());
}

// A real tool that records that it ran and returns real content.
static std::atomic<int> g_tool_runs{0};

int main() {
    // Unbuffered: a native fault must not discard the evidence measured so far.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("B3 tool-authority + same-session continuation\n");
    std::printf("----------------------------------------------------------\n");

    // The bound authority MUST outlive every binder. BindAgentToolAuthority
    // stores a raw pointer, so binding a block-scoped registry leaves the
    // process-wide authority dangling. That is a real API hazard, not a test
    // artifact: it is why the authority is hoisted to function scope here.
    // Declared here but NOT bound yet, so T1 can observe the unbound state.
    static AgentToolRegistry authority;

    // ---------------------------------------------------------------- T1
    // Unbound-authority behaviour must be checked BEFORE any binding exists.
    // (The static authority above is bound lazily at first use, so this block
    // runs first and observes the genuinely unbound state.)
    {
        ToolRegistry reg;
        reg.use_canonical_authority(true);
        if (RawrXD::Agentic::IsAgentToolAuthorityBound()) {
            std::printf("%-46s %s   %s\n", "T1 unbound-authority precondition", "FAIL",
                        "authority already bound; cannot test fail-closed path");
            ++g_fail;
        } else {
            std::string result, err;
            const bool ok = reg.execute("file.read", "{}", result, err);
            check("T1 unbound authority fails closed", !ok && !err.empty(),
                  "rc=false err=" + err.substr(0, 58));
        }
    }

    // ---------------------------------------------------------------- T2
    {
        RawrXD::Agentic::BindAgentToolAuthority(authority);

        ToolDescriptor desc;
        desc.id = "file.read";
        desc.description = "read a file";
        authority.registerTool(
            desc,
            [](const RawrXD::Agentic::ToolRequest&,
               RawrXD::Agentic::ToolContext&) -> RawrXD::Agentic::ToolResult {
                ++g_tool_runs;
                RawrXD::Agentic::ToolResult r;
                r.exit_code = 0;
                r.stdout_text = "REAL_TOOL_OUTPUT";
                return r;
            });

        ToolRegistry reg;
        reg.use_canonical_authority(true);

        // add() must be rejected in canonical mode.
        bool addRejected = false;
        std::string addErr;
        try {
            reg.add("sneaky", [](std::string_view, std::string&, std::string&) { return true; });
        } catch (const std::exception& e) {
            addRejected = true;
            addErr = e.what();
        }
        check("T2 add() rejected in canonical mode", addRejected, addErr.substr(0, 52));

        const auto before = RawrXD::Agentic::g_agentToolInvocations.load();
        std::string out, err;
        const bool ok = reg.execute("file.read", "{\"path\":\"x\"}", out, err);
        const auto after = RawrXD::Agentic::g_agentToolInvocations.load();
        check("T2 tool executed via canonical authority",
              ok && out == "REAL_TOOL_OUTPUT", "out=" + out);
        check("T2 authority counter incremented",
              after == before + 1,
              std::to_string(before) + "->" + std::to_string(after));
        check("T2 handler actually ran", g_tool_runs.load() == 1,
              "runs=" + std::to_string(g_tool_runs.load()));

        std::string o2, e2;
        const bool ok2 = reg.execute("no.such.tool", "{}", o2, e2);
        check("T2 unknown tool rejected", !ok2, e2.substr(0, 52));
    }

    // ---------------------------------------------------------------- T3
    // Same-session continuation: model asks for a tool, gets a REAL answer
    // from the canonical authority, and resumes in the SAME session.
    {
        ToolRegistry tools;
        tools.use_canonical_authority(true);

        std::atomic<int> decode_calls{0};
        std::atomic<int> append_calls{0};
        std::string last_tool_name, last_tool_result;
        std::atomic<bool> tool_seen_by_model{false};

        ModelBindings model;
        model.prefill = [](std::string_view, std::string&) { return true; };

        model.decode_one = [&]() -> DecodeResult {
            const int n = ++decode_calls;
            DecodeResult r;
            if (n == 1) {
                r.kind = DecodeKind::ToolCall;
                r.tool.name = "file.read";
                r.tool.arguments = "{\"path\":\"target.cpp\"}";
            } else if (n == 2) {
                // The model must be able to SEE the tool result to answer.
                r.kind = DecodeKind::Text;
                r.text = "answer-after-observation";
                r.token_id = 42;
            } else {
                // Without an explicit end the session keeps decoding forever,
                // which is correct runtime behaviour and a hung test.
                r.kind = DecodeKind::Eos;
            }
            return r;
        };

        model.append_tool_result =
            [&](std::string_view name, std::string_view result, std::string&) {
                ++append_calls;
                last_tool_name = std::string(name);
                last_tool_result = std::string(result);
                // If the observation really carried the tool output, the model
                // can now report it. This is what makes the run a continuation
                // rather than a fresh guess.
                if (last_tool_result.find("REAL_TOOL_OUTPUT") != std::string::npos) {
                    tool_seen_by_model = true;
                }
                return true;
            };

        model.cancel = [] {};

        // Session::validate_bindings() requires ALL FIVE bindings, including
        // the optional-looking progress sink. Omitting it throws from the
        // constructor, which escapes main as std::terminate (0xC0000409).
        // The harness installs a real sink so the session exercises its actual
        // progress path rather than a null hook.
        model.set_progress_sink =
            [](std::function<void(std::uint64_t, std::uint32_t, std::uint32_t,
                                 std::string_view)> sink) {
                if (sink) sink(1, 0, 1, "harness-progress");
            };

        std::atomic<bool> final_text_seen{false};
        std::atomic<int> tool_observed{0};
        std::atomic<std::uint64_t> epochs{0};
        std::string failure_text;   // captured from the stream, not guessed

        auto tools_shared = std::make_shared<ToolRegistry>();
        tools_shared->use_canonical_authority(true);
        auto events = std::make_shared<EventPipe>();

        // Drain events on a watcher thread so the assertions observe the real
        // published stream rather than an internal counter.
        std::atomic<bool> drain_stop{false};
        std::thread watcher([&] {
            Event ev;
            while (!drain_stop.load()) {
                if (!events->wait_pop(ev, drain_stop)) break;
                if (ev.kind == EventKind::ToolCall) ++tool_observed;
                if (ev.kind == EventKind::FinalText) final_text_seen = true;
                if (ev.kind == EventKind::Error && failure_text.empty()) {
                    failure_text = ev.text.empty() ? ev.payload : ev.text;
                }
                epochs.store(ev.work_epoch);
            }
        });

        Session session(7, model, tools_shared, events, nullptr);
        Request req;
        req.prompt = "read target.cpp and tell me what is in it";
        session.start(req);
        session.join();
        drain_stop.store(true);
        events->close();
        watcher.join();

        const bool completed = session.state() == State::Completed;

        check("T3 same session: decode resumed after tool",
              decode_calls.load() >= 2,
              "decode_calls=" + std::to_string(decode_calls.load()));
        check("T3 append_tool_result called once", append_calls.load() == 1,
              "append_calls=" + std::to_string(append_calls.load()));
        check("T3 tool was the canonical one", last_tool_name == "file.read",
              last_tool_name);
        check("T3 observation carried REAL tool output",
              last_tool_result.find("REAL_TOOL_OUTPUT") != std::string::npos,
              "result=" + last_tool_result.substr(0, 40));
        check("T3 model condition on observation satisfied", tool_seen_by_model.load(),
              "1");
        check("T3 ToolCall event published", tool_observed.load() >= 1,
              "tool_events=" + std::to_string(tool_observed.load()));
        check("T3 session reached Completed", completed,
              "state=" + std::to_string((int)session.state()) +
                  " fail=[" + failure_text.substr(0, 70) + "]");
    }

    std::printf("----------------------------------------------------------\n");
    std::printf("B3_FAIL=%d  VERDICT=%s\n", g_fail, g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
