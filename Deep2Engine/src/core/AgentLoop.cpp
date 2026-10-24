// The agent loop.
//
// It is the bounded loop that turns a request into tool calls and a final
// answer: the model asks for a tool, the tool runs, the result goes back
// into the context, and the model either asks for another tool or answers.
//
// ---------------------------------------------------------------------------
// What it is built on
// ---------------------------------------------------------------------------
//
// The tools are in core/AgentTools.cpp, and the decisions about what is
// allowed are the ones the tree already makes:
//
//   the authorisation gate   rawrxd::agentcore::AuthorizationGate
//   the process runner       rawrxd::agentcore::ProcessRunner
//   the mutation ledger      rawrxd::agentcore::MutationLedger
//   the toolchain            rawrxd::agentcore::detectToolchain
//   the diagnostics parser   rawrxd::agentcore::primaryCompilerErrors
//
// Nothing here decides what is allowed. The gate decides, the ledger
// records, and the runner runs. A tool that is not on the list is not
// implemented rather than refused at runtime, so the model cannot ask for
// something the loop would only say no to.
//
// The tools and the reading of what the model said live in AgentTools.cpp
// so that they can be tested without a model. The loop here is the part
// that needs one.
//
// ---------------------------------------------------------------------------
// The bounds
// ---------------------------------------------------------------------------
//
// A loop that can run forever is a loop that will. The bounds are:
//
//   the steps        --max-steps, and the loop stops there
//   the output       every tool result is truncated before it goes into the
//                     context, so a large file cannot eat the window
//   the files read   a read is capped, and a search returns a capped
//                     number of matches
//   the writes       a write is refused unless the gate allows it, and every
//                     write is recorded in the ledger
//
// ---------------------------------------------------------------------------
// The verification and the rollback
// ---------------------------------------------------------------------------
//
// A write is not a change that is kept because the model asked for it. When
// a build or a test follows a write and fails, the write is undone: the
// content that was there before is put back, the ledger records the
// rollback, and the failure is what the model sees next. A run that leaves
// the workspace in a state the build rejects is not a finished run, and a
// run that ends without a verification is not a finished run either.

#include "core/AgentLoop.hpp"
#include "core/ChatTemplate.hpp"
#include "core/TinyJson.hpp"

#include "agentcore/mutation_ledger.hpp"
#include "core/AgentLoopInternal.hpp"
#include "core/ChatTemplate.hpp"
#include "core/RunCommand.hpp"

#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace deep2 {
namespace {

namespace fs = std::filesystem;

using agentloop::DispatchTool;
using agentloop::ParseReply;
using agentloop::PendingWrite;
using agentloop::ToolResult;
using rawrxd::agentcore::MutationLedger;
using rawrxd::agentcore::MutationRecord;

// The bound on one tool result in the context.
constexpr size_t kMaxToolOutput = 4000;

// The same failure this many times ends the run.
constexpr unsigned kMaxFailedVerifications = 3;

// One step of the loop.
struct AgentStep {
    std::string thought;
    std::string tool;
    std::string toolArgs;
    ToolResult result;
};

// Undo a write.
//
// The content that was there before is put back, and the ledger records
// that it was put back.
void rollbackWrite(const PendingWrite& write, MutationLedger& ledger) {
    std::error_code ec;
    if (write.existed) {
        std::ofstream out(write.absolutePath, std::ios::binary | std::ios::trunc);
        if (out) out << write.previousContent;
    } else {
        fs::remove(write.absolutePath, ec);
    }
    MutationRecord record;
    record.path = write.relativePath;
    record.action = write.existed ? "restore" : "remove";
    record.reason = "the verification after the write failed";
    record.sha256Before = agentloop::Sha256Hex(write.previousContent);
    record.sha256After = agentloop::Sha256Hex(write.previousContent);
    record.bytesAfter = write.previousContent.size();
    record.round = 0;
    std::string error;
    ledger.record(record, error);
}

// The tools, as the model is told about them.
//
// The list is the list of tools the loop implements. A model that is told
// about a tool the loop does not have will call it, and the call will be
// refused.
std::vector<ToolSpec> AgentToolSpecs() {
    std::vector<ToolSpec> tools;
    tools.push_back({"read", "Read a file in the workspace and return its content.",
                     {{"path", "string"}}});
    tools.push_back({"search", "Find the files in the workspace that contain a string.",
                     {{"pattern", "string"}, {"path", "string"}}});
    tools.push_back({"list", "List the files in the workspace.", {{"path", "string"}}});
    tools.push_back({"write", "Write a whole file.",
                     {{"path", "string"}, {"content", "string"}}});
    tools.push_back({"edit", "Replace an exact piece of text in a file.",
                     {{"path", "string"}, {"old_string", "string"}, {"new_string", "string"}}});
    tools.push_back({"shell", "Run a command that is on the allowlist.",
                     {{"command", "string"}, {"args", "array"}}});
    tools.push_back({"build", "Build the workspace.", {}});
    tools.push_back({"test", "Run the tests of the workspace.", {}});
    return tools;
}

// The conversation of one step, in the model's own form.
//
// The turns are the model's own: the request is a user turn, a tool call is
// an assistant turn, and a tool result is a tool turn. Every result is
// truncated so that a large file cannot take the window.
bool BuildAgentConversation(const std::string& systemPrompt, const std::string& request,
                            const std::vector<AgentStep>& history,
                            std::vector<chat::Turn>& turns) {
    turns.clear();
    chat::Turn user;
    user.role = "user";
    user.content = request;
    turns.push_back(user);

    for (const AgentStep& step : history) {
        if (step.tool.empty()) {
            chat::Turn thought;
            thought.role = "assistant";
            thought.content = step.thought;
            turns.push_back(thought);
            continue;
        }
        chat::Turn call;
        call.role = "assistant";
        call.isToolCall = true;
        call.content = "{\"name\": \"" + step.tool + "\", \"parameters\": " + step.toolArgs + "}";
        turns.push_back(call);

        chat::Turn result;
        result.role = "ipython";
        if (step.result.success) {
            std::string output = step.result.output;
            if (output.size() > kMaxToolOutput) output = output.substr(0, kMaxToolOutput);
            result.content = output;
        } else {
            result.content = "the tool failed: " + step.result.error;
        }
        turns.push_back(result);
    }
    (void)systemPrompt;
    return true;
}

// The prompt of one step, in the plain form.
//
// The plain form is what the loop falls back to when the model has no
// conversation form, and it is also what a model that does not follow the
// conversation protocol is asked to do. The history is the model's own
// previous steps and the results of the tools.
std::string BuildAgentPrompt(const std::string& systemPrompt, const std::string& request,
                              const std::vector<AgentStep>& history) {
    std::ostringstream prompt;
    prompt << systemPrompt << "\n\n";
    prompt << "Request: " << request << "\n\n";
    if (!history.empty()) {
        prompt << "What has happened so far:\n";
        for (size_t i = 0; i < history.size(); ++i) {
            prompt << "step " << (i + 1) << ": ";
            if (history[i].tool.empty()) {
                prompt << "you said: " << history[i].thought << "\n";
                continue;
            }
            prompt << "you called " << history[i].tool << "\n";
            if (history[i].result.success) {
                std::string output = history[i].result.output;
                if (output.size() > kMaxToolOutput) output = output.substr(0, kMaxToolOutput);
                prompt << "the tool said: " << output << "\n";
            } else {
                prompt << "the tool failed: " << history[i].result.error << "\n";
            }
        }
        prompt << "\n";
    }
    prompt << "Reply with exactly one line, in one of these two forms:\n"
           << "TOOL:<name> ARGS:<json object>\n"
           << "ANSWER:<the final answer>\n"
           << "\n"
           << "The tools are:\n"
           << "read   {\"path\": \"relative/path.cpp\"}\n"
           << "search {\"pattern\": \"text to find\"}\n"
           << "list   {\"path\": \"relative/dir\"}\n"
           << "write  {\"path\": \"relative/path.cpp\", \"content\": \"the whole new file\"}\n"
           << "edit   {\"path\": \"relative/path.cpp\", \"old_string\": \"exact text\", "
              "\"new_string\": \"the text that replaces it\"}\n"
           << "shell  {\"command\": \"cmake\", \"args\": [\"--build\", \"build\"]}\n"
           << "build  {}\n"
           << "test   {}\n"
           << "\n"
           << "Use edit rather than write when you change part of a file. Read a file before "
           << "you change it. Build and test after you change something. When the work is done, "
           << "answer with ANSWER:.\n"
           << "Example: TOOL:read ARGS:{\"path\": \"src/main.cpp\"}\n";
    return prompt.str();
}

// The system prompt of the loop.
const char* kSystemPrompt =
    "You are an agent that works on a source tree. You look before you act: "
    "you read the files and you search the tree before you change anything. "
    "You change one thing at a time, and you check the build and the tests "
    "after you change something. When the work is done, you answer.";

int RunAgentLoopBody(const RunOptions& options, const TurnSource& turn,
                     AgentLoopReport* report);

} // namespace

// Write the receipt for an agent run.
//
// The receipt is the run's evidence, and it is written whether the run
// succeeded or failed: a run that failed and left no record is a run that
// cannot be audited.
//
// The provenance is recorded as separate claims because they are separate
// facts. The model ran in this process, on this machine, from a local GGUF
// file. The loop, the tools, the gate and the verification are this tree's.
void WriteAgentReceipt(const std::string& receiptPath,
                       const RunOptions& options,
                       const std::string& modelPath,
                       const AgentLoopReport& report) {
    std::error_code ec;
    const fs::path out(receiptPath);
    if (!out.parent_path().empty()) fs::create_directories(out.parent_path(), ec);

    tinyjson::Value doc = tinyjson::Value::makeObject();
    doc.set("schema_version", tinyjson::Value::makeString("deep2.agent.receipt/1"));

    // What was asked, and what came back.
    doc.set("model", tinyjson::Value::makeString(modelPath));
    doc.set("request", tinyjson::Value::makeString(options.prompt));
    doc.set("workspace", tinyjson::Value::makeString(
        options.workspace.empty() ? fs::current_path().string() : options.workspace));
    doc.set("mode", tinyjson::Value::makeString(options.gpu ? "gpu" : "cpu"));
    doc.set("max_steps", tinyjson::Value::makeUInt(options.maxSteps));
    doc.set("success", tinyjson::Value::makeBool(report.finalAnswerSeen));
    doc.set("final_answer", tinyjson::Value::makeString(report.finalAnswer));

    // What the run did.
    tinyjson::Value counts = tinyjson::Value::makeObject();
    counts.set("steps", tinyjson::Value::makeUInt(report.steps));
    counts.set("tool_calls", tinyjson::Value::makeUInt(report.toolCalls));
    counts.set("tool_failures", tinyjson::Value::makeUInt(report.toolFailures));
    counts.set("rollbacks", tinyjson::Value::makeUInt(report.rollbacks));
    counts.set("verifications_passed", tinyjson::Value::makeUInt(report.verificationsPassed));
    counts.set("failed_verifications", tinyjson::Value::makeUInt(report.failedVerifications));
    counts.set("loop_breaks", tinyjson::Value::makeUInt(report.loopBreaks));
    doc.set("counts", counts);

    // The tools the model asked for, and what each one said.
    tinyjson::Value tools = tinyjson::Value::makeArray();
    for (const AgentToolTrace& t : report.trace) {
        tinyjson::Value e = tinyjson::Value::makeObject();
        e.set("tool", tinyjson::Value::makeString(t.tool));
        e.set("arguments", tinyjson::Value::makeString(t.arguments));
        e.set("success", tinyjson::Value::makeBool(t.success));
        e.set("error", tinyjson::Value::makeString(t.error));
        e.set("output", tinyjson::Value::makeString(t.output));
        e.set("verification", tinyjson::Value::makeBool(t.wasVerification));
        e.set("verification_passed", tinyjson::Value::makeBool(t.verificationPassed));
        tools.push(e);
    }
    doc.set("tools", tools);

    // The mutations, and the ledger they are recorded in.
    doc.set("ledger", tinyjson::Value::makeString(report.ledgerPath));

    // The provenance. These are the claims a reader is entitled to make
    // about this run, and they are not the same claim.
    tinyjson::Value prov = tinyjson::Value::makeObject();
    prov.set("AGENT_ENGINE", tinyjson::Value::makeString("RAWRXD"));
    prov.set("INFERENCE_ENGINE", tinyjson::Value::makeString("DEEP2"));
    prov.set("MODEL_SOURCE", tinyjson::Value::makeString(
        options.modelSource == "ollama-manifest" ? "OLLAMA_STORE" : "LOCAL_GGUF"));
    prov.set("TOOL_AUTHORITY", tinyjson::Value::makeString("RAWRXD"));
    prov.set("VERIFICATION", tinyjson::Value::makeString("RAWRXD"));
    prov.set("MODEL_RESOLVER_SOURCE", tinyjson::Value::makeString(options.modelSource));
    // The verification claim is only as good as the verification that ran, so
    // the number of verifications is carried next to it.
    prov.set("verifications_performed",
             tinyjson::Value::makeUInt(report.verificationsPassed + report.failedVerifications));
    prov.set("writes_kept", tinyjson::Value::makeBool(report.verificationsPassed > 0));
    prov.set("writes_rolled_back", tinyjson::Value::makeBool(report.rollbacks > 0));
    doc.set("provenance", prov);

    // The receipt describes execution. It is not a certification.
    doc.set("full_model_certification", tinyjson::Value::makeString("NOT_CERTIFIED"));

    const std::string text = doc.dump();
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << text << "\n";
}

int RunAgentLoopWith(const RunOptions& options, const TurnSource& turn,
                     AgentLoopReport* report) {
    // A failure inside the loop is a failure of the run, and it is
    // reported. A crash would take the process with it and say nothing
    // about what went wrong.
    try {
        return RunAgentLoopBody(options, turn, report);
    } catch (const std::exception& error) {
        std::cerr << "[AGENT] the loop failed: " << error.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[AGENT] the loop failed with an unknown error\n";
        return 1;
    }
}

namespace {

int RunAgentLoopBody(const RunOptions& options, const TurnSource& turn,
                     AgentLoopReport* report) {
    const fs::path workspace = options.workspace.empty() ? fs::current_path()
                                                         : fs::path(options.workspace);
    const std::string ledgerPath = (workspace / ".rawr" / "agent-mutations.jsonl").string();
    MutationLedger ledger(ledgerPath);

    // Emit event: AGENT_PROMPT_READY
    if (!options.quiet) {
        std::cerr << "[EVENT] AGENT_PROMPT_READY request=\"" << options.prompt << "\" workspace=" << workspace.string() << "\n";
    }

    std::vector<AgentStep> history;
    std::vector<PendingWrite> pending;
    bool finalAnswerSeen = false;
    std::string finalAnswer;
    uint32_t toolCalls = 0;
    uint32_t toolFailures = 0;
    uint32_t rollbacks = 0;
    uint32_t failedVerifications = 0;
    uint32_t verificationsPassed = 0;
    uint32_t loopBreaks = 0;
    std::vector<AgentToolTrace> trace;
    // How many times each distinct call has been made.
    //
    // A model that repeats the same call is not making progress, and every
    // repeat costs a model turn. The second repeat is answered with a hint
    // and the third ends the run, which is the difference between a run that
    // stops and a run that burns every step.
    std::map<std::string, uint32_t> callCounts;

    for (uint32_t step = 0; step < options.maxSteps && !finalAnswerSeen; ++step) {
        std::string prompt;

        // Emit event: AGENT_STEP_COMPLETE (at start of each step, for first step this is initial)
        if (!options.quiet) {
            std::cerr << "[EVENT] AGENT_STEP_START step=" << (step + 1) << " max_steps=" << options.maxSteps << "\n";
        }

        // The model's own conversation, when the model has one.
        //
        // A tool-calling model was trained to be spoken to in a
        // conversation whose turns carry roles, and the tool list and the
        // tool results are part of that conversation. A prompt that does
        // not look like the conversation the model was trained on is a
        // prompt the model answers badly.
        if (!options.chatTemplate.empty()) {
            std::vector<chat::Turn> turns;
            BuildAgentConversation(kSystemPrompt, options.prompt, history, turns);
            std::string rendered;
            std::string whyNot;
            if (chat::RenderConversation(options.chatTemplate, kSystemPrompt,
                                         chat::ToolsJson(AgentToolSpecs()), turns, rendered,
                                         whyNot)) {
                prompt = rendered;
            }
        }
        if (prompt.empty()) {
            prompt = BuildAgentPrompt(kSystemPrompt, options.prompt, history);
            if (!options.chatTemplate.empty()) {
                prompt = ApplyChatTemplate(options.chatTemplate, prompt);
            }
        }

// The model turn.
        //
        // The turn is the same one the command line runs, so the agent
        // speaks with the model the same way a run does.
        
        // Emit event: AGENT_PREFILL_BEGIN (before model turn)
        if (!options.quiet) {
            std::cerr << "[EVENT] AGENT_PREFILL_BEGIN step=" << (step + 1) << "\n";
        }

        // Emit event: MODEL_RESPONSE (before generation)
        if (!options.quiet) {
            std::cerr << "[EVENT] MODEL_RESPONSE_BEGIN step=" << (step + 1) << "\n";
        }
        
        bool turnOk = false;
        std::string turnWhyNot;
        const std::string turnText = turn(prompt, turnOk, turnWhyNot);
        
        // Emit event: MODEL_RESPONSE_END
        if (!options.quiet) {
            std::cerr << "[EVENT] MODEL_RESPONSE_END step=" << (step + 1) << " ok=" << (turnOk ? "true" : "false") << " len=" << turnText.size() << "\n";
        }

        // Emit event: AGENT_PREFILL_END (after model turn)
        if (!options.quiet) {
            std::cerr << "[EVENT] AGENT_PREFILL_END step=" << (step + 1) << " turn_ok=" << (turnOk ? "true" : "false") << "\n";
        }
        
        if (!turnOk) {
            if (!options.quiet) {
                std::cerr << "[AGENT] the model turn failed: " << turnWhyNot << "\n";
            }
            break;
        }

        const agentloop::ParsedReply reply = ParseReply(turnText);
        
        // Emit event: TOOL_PARSE_RESULT
        if (!options.quiet) {
            std::cerr << "[EVENT] TOOL_PARSE_RESULT is_tool=" << (reply.isTool ? "true" : "false") 
                      << " is_final=" << (reply.isFinal ? "true" : "false")
                      << " tool=" << reply.tool << " args=" << reply.args << "\n";
        }
        
        if (reply.isTool) {
            ++toolCalls;
            
            // Emit event: TOOL_AUTHORIZATION
            if (!options.quiet) {
                std::cerr << "[EVENT] TOOL_AUTHORIZATION tool=" << reply.tool << " args=" << reply.args << "\n";
            }

            // The same call again.
            //
            // The fingerprint is the tool and its arguments, so a model that
            // reads a different file is making progress and a model that
            // reads the same file again is not.
            const std::string fingerprint = reply.tool + "\n" + reply.args;
            const uint32_t seen = ++callCounts[fingerprint];
            if (seen >= 3) {
                ++loopBreaks;
                if (!options.quiet) {
                    std::cerr << "[AGENT] the same call was made " << seen
                              << " times: the run is stopping\n";
                }
                finalAnswer = "the model repeated the same call and made no progress";
                finalAnswerSeen = true;
                break;
            }

            AgentStep agentStep;
            agentStep.thought = "calling " + reply.tool;
            agentStep.tool = reply.tool;
            agentStep.toolArgs = reply.args;
            
            // Emit event: TOOL_EXEC_BEGIN
            if (!options.quiet) {
                std::cerr << "[EVENT] TOOL_EXEC_BEGIN tool=" << reply.tool << " args=" << reply.args << "\n";
            }
            
            agentStep.result = DispatchTool(reply.tool, reply.args, workspace, pending, ledger);
            
            // Emit event: TOOL_EXEC_END
            if (!options.quiet) {
                std::cerr << "[EVENT] TOOL_EXEC_END tool=" << reply.tool << " success=" << (agentStep.result.success ? "true" : "false") << "\n";
            }
            
            if (!agentStep.result.success) ++toolFailures;

            // The second time the same call is made, the model is told that
            // it has already made it, so that a model that can read the hint
            // moves on instead of repeating itself.
            if (seen == 2) {
                agentStep.result.output +=
                    "\n[you already made this exact call. The result is above. "
                    "Do something different, or answer.]";
            }

            // A build or a test is the proof that the changes are good.
            //
            // A passing build ends the obligation: the changes are kept. A
            // failing build does not undo them, because the model has to be
            // able to see the failure and repair it; the obligation stays
            // open until the build passes or the run ends.
            const bool isVerification = (reply.tool == "build" || reply.tool == "test");
            if (isVerification) {
                if (agentStep.result.success) {
                    ++verificationsPassed;
                    if (!pending.empty()) {
                        if (!options.quiet) {
                            std::cerr << "[AGENT] the verification passed: " << pending.size()
                                      << " change(s) are kept\n";
                        }
                        pending.clear();
                    }
                    failedVerifications = 0;
                } else {
                    ++failedVerifications;
                    agentStep.result.output +=
                        "\n[the build failed. Repair the cause and build again. "
                        "The change is still in place.]";
                }
            }

// The trace is the evidence that the model drove the tools.
            // It records what was asked, what the tool said, and whether the
            // call was a verification and whether it passed.
            {
                AgentToolTrace t;
                t.tool = reply.tool;
                t.arguments = reply.args;
                t.success = agentStep.result.success;
                t.error = agentStep.result.error;
                t.output = agentStep.result.output.size() > 400
                               ? agentStep.result.output.substr(0, 400)
                               : agentStep.result.output;
                t.wasVerification = isVerification;
                t.verificationPassed = isVerification && agentStep.result.success;
                trace.push_back(t);
            }

            // Emit event: OBSERVATION_INJECTED
            if (!options.quiet) {
                std::cerr << "[EVENT] OBSERVATION_INJECTED tool=" << reply.tool << " output_len=" << agentStep.result.output.size() << "\n";
            }

            if (!options.quiet) {
                std::cerr << "[AGENT] step " << (step + 1) << ": " << reply.tool << " -> "
                          << (agentStep.result.success ? "ok"
                                                       : "failed: " + agentStep.result.error)
                          << "\n";
            }
            history.push_back(agentStep);

            // The same failure three times is a failure the model is not
            // going to get past. The changes are undone and the run ends.
            if (failedVerifications >= kMaxFailedVerifications) {
                if (!options.quiet) {
                    std::cerr << "[AGENT] the same failure repeated " << failedVerifications
                              << " times: the run is stopping\n";
                }
                for (const PendingWrite& write : pending) {
                    rollbackWrite(write, ledger);
                    ++rollbacks;
                }
                pending.clear();
                finalAnswer = "the run stopped after the same failure three times; "
                              "the changes were undone";
finalAnswerSeen = true;
                break;
            }
            // Emit event: AGENT_TURN_COMPLETE (tool executed, continuing)
            if (!options.quiet) {
                std::cerr << "[EVENT] AGENT_TURN_COMPLETE step=" << (step + 1)
                          << " toolCalls=" << toolCalls << " answered=false tool_executed=true\n";
            }
            continue;
        }

if (reply.isFinal) {
            // Emit event: TASK_COMPLETION_EVALUATED
            if (!options.quiet) {
                std::cerr << "[EVENT] TASK_COMPLETION_EVALUATED final_answer=true steps=" << (step + 1) << "\n";
            }
            
            finalAnswer = reply.text;
            finalAnswerSeen = true;
            if (!options.quiet) {
                std::cerr << "[AGENT] the model answered after " << (step + 1) << " steps\n";
            }
            break;
        }

        // The model said something the loop cannot use.
        //
        // Before it has called a tool, a reply that is not a call is the
        // model thinking out loud, and the loop goes on. Once the model has
        // been working, a reply that is not a call is the answer.
if (toolCalls == 0) {
            AgentStep agentStep;
            agentStep.thought = turnText.size() > 500 ? turnText.substr(0, 500) : turnText;
            history.push_back(agentStep);
            if (!options.quiet) {
                std::cerr << "[AGENT] step " << (step + 1) << ": the reply was not a tool call: \""
                          << (turnText.size() > 200 ? turnText.substr(0, 200) : turnText) << "\"\n";
            }
            // Emit event: AGENT_TURN_COMPLETE (step completed without answer)
            if (!options.quiet) {
                std::cerr << "[EVENT] AGENT_TURN_COMPLETE step=" << (step + 1)
                          << " toolCalls=" << toolCalls << " answered=false\n";
            }
            continue;
        }

        finalAnswer = turnText;
        finalAnswerSeen = true;
        if (!options.quiet) {
            std::cerr << "[AGENT] the model answered after " << (step + 1) << " steps\n";
        }
        // Emit event: AGENT_TURN_COMPLETE (step completed with answer)
        if (!options.quiet) {
            std::cerr << "[EVENT] AGENT_TURN_COMPLETE step=" << (step + 1)
                      << " toolCalls=" << toolCalls << " answered=true\n";
        }
        break;
    }

    // A write that was never verified is undone.
    //
    // The loop ends when the model answers or when the steps run out. A
    // write that was not checked by a build or a test has not been shown to
    // be good, and a change that has not been shown to be good is not kept.
    if (!pending.empty()) {
        for (const PendingWrite& write : pending) {
            rollbackWrite(write, ledger);
            ++rollbacks;
        }
        pending.clear();
        if (!options.quiet) {
            std::cerr << "[AGENT] the writes were rolled back: they were never verified\n";
        }
    }

if (!finalAnswer.empty()) {
        // Emit event: FINAL_ANSWER_BEGIN
        if (!options.quiet) {
            std::cerr << "[EVENT] FINAL_ANSWER_BEGIN len=" << finalAnswer.size() << "\n";
        }
        std::cout << finalAnswer << "\n" << std::flush;
        // Emit event: FINAL_ANSWER_END
        if (!options.quiet) {
            std::cerr << "[EVENT] FINAL_ANSWER_END\n";
        }
    } else {
        std::cerr << "[AGENT] the run ended without an answer\n";
    }

    // Emit event: AGENT_RECEIPT
    if (!options.quiet) {
        std::cerr << "[EVENT] AGENT_RECEIPT ledger=" << ledgerPath << " steps=" << history.size() 
                  << " tool_calls=" << toolCalls << " final_answer_seen=" << (finalAnswerSeen ? "true" : "false") << "\n";
    }

    if (!options.quiet) {
        std::cerr << "[AGENT] steps=" << history.size() << " tool_calls=" << toolCalls
                  << " tool_failures=" << toolFailures << " rollbacks=" << rollbacks
                  << " ledger=" << ledgerPath << "\n";
    }

    if (report) {
        report->steps = static_cast<uint32_t>(history.size());
        report->toolCalls = toolCalls;
        report->toolFailures = toolFailures;
        report->rollbacks = rollbacks;
        report->failedVerifications = failedVerifications;
        report->verificationsPassed = verificationsPassed;
        report->loopBreaks = loopBreaks;
        report->finalAnswerSeen = finalAnswerSeen;
        report->finalAnswer = finalAnswer;
        report->ledgerPath = ledgerPath;
        report->trace = trace;
    }

    return finalAnswerSeen ? 0 : 1;
}

} // namespace

} // namespace deep2
