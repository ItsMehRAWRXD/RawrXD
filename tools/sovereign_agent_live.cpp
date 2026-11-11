// =============================================================================
// sovereign_agent_live.cpp — end-to-end proof harness for the Sovereign Agent
// Core (src/agentic/sovereign_agent.hpp) against the REAL Deep2 backend.
//
// This is the milestone the source drop names explicitly: "connecting this core
// to rawr.exe ask, then proving a complete model -> tool -> observation ->
// model -> verified answer cycle." No synthetic model: Decision parsing reads
// the live completion from the local llama.cpp-compatible server (127.0.0.1:
// 8080, the same endpoint rawr_core.hpp uses). Nothing is simulated, and the
// exit code is gated on the host evidence ledger, not on model prose.
// =============================================================================
#include "agentic/sovereign_agent.hpp"
#include "rawr_core.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace rawrxd;

// ---------------------------------------------------------------------------
// Real Deep2-backed model adapter: typed decisions only.
//
// Contract sent to the model EVERY turn — reply with exactly one JSON object:
//   {"decision":"final","answer":"..."}
//   {"decision":"tool","tool":"search_text","path":".","query":"..."}
// Anything unparseable is DecisionKind::Invalid and the host stops the run
// with a failure; prose is never reinterpreted as a command.
//
// Host policy (controller decides HOW the answer may be produced): a question
// that asks what the repository contains may not be answered before the host
// has executed at least one tool. A premature final is refused back to the
// model with an instruction to search, so the model->tool->observation->model
// cycle is actually exercised instead of short-circuited.
// ---------------------------------------------------------------------------
static const char* kContract =
    "You are RawrXD's sovereign agent. Reply with exactly one JSON object.\n"
    "To search the workspace for a literal string:\n"
    "{\"decision\":\"tool\",\"tool\":\"search_text\",\"path\":\".\","
    "\"query\":\"KQuantRowDotQ8\"}\n"
    "To give the final answer:\n"
    "{\"decision\":\"final\",\"answer\":\"your answer here\"}\n"
    "Cite only real tool output shown above. Never claim a tool ran unless a "
    "TOOL message with executed=1 appears above. Never repeat a cached "
    "duplicate call.";

static bool isRepositoryQuestion(const std::string& q) {
    const std::string low = ascii_lower(q);
    static const char* cues[] = {
        "which files", "how many", "where is", "where are", "which file",
        "find the", "search", "in src", "in the repo", "defined", "referenced",
        "implemented", "exists"
    };
    for (const char* c : cues)
        if (low.find(c) != std::string::npos) return true;
    return false;
}

// Extract the first balanced {...} block. Returns {} when none is well-formed.
static std::string firstJsonObject(const std::string& s) {
    size_t start = s.find('{');
    if (start == std::string::npos) return {};
    int depth = 0;
    bool inStr = false;
    for (size_t i = start; i < s.size(); ++i) {
        const char c = s[i];
        if (inStr) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') inStr = false;
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '{') ++depth;
        if (c == '}') {
            if (--depth == 0) return s.substr(start, i - start + 1);
        }
    }
    return {};
}

class LiveModelAdapter : public ModelAdapter {
public:
    LiveModelAdapter(rawr::InferenceClient& client, int maxTokens,
                     bool repositoryQuestion)
        : client_(client), maxTokens_(maxTokens),
          repositoryQuestion_(repositoryQuestion) {}

    Decision next(const AgentState& state) override {
        const bool hasExecution =
            std::any_of(state.ledger.begin(), state.ledger.end(),
                        [](const Observation& o) { return o.executed; });

        // First pass with the strict contract.
        Decision d = askOnce(state);
        // Host policy: refuse a premature final on a repository question.
        if (d.kind == DecisionKind::Final && repositoryQuestion_ &&
            !hasExecution && refused_ < 2) {
            ++refused_;
            std::vector<json> messages;
            messages.push_back({{"role", "system"}, {"content", kContract}});
            for (const auto& m : state.history) {
                const char* role = "user";
                switch (m.role) {
                    case Message::Role::System:    role = "system";    break;
                    case Message::Role::User:      role = "user";      break;
                    case Message::Role::Assistant: role = "assistant"; break;
                    case Message::Role::Tool:      role = "user";      break;
                }
                messages.push_back({{"role", role}, {"content", m.content}});
            }
            messages.push_back(
                {{"role", "user"},
                 {"content",
                  "REFUSED: this is a question about what the repository "
                  "contains, and no host tool has executed yet. Reply with the "
                  "tool JSON now, e.g. "
                  "{\"decision\":\"tool\",\"tool\":\"search_text\","
                  "\"path\":\"src\",\"query\":\"<symbol or phrase>\"}."}});
            rawr::InferenceResult r = client_.complete(messages, maxTokens_);
            if (!r.ok) throw std::runtime_error(r.error.empty() ? "backend failure" : r.error);
            return parseDecision(r.content);
        }
        return d;
    }

private:
    Decision askOnce(const AgentState& state) {
        std::vector<json> messages;
        messages.push_back({{"role", "system"}, {"content", kContract}});
        for (const auto& m : state.history) {
            const char* role = "user";
            switch (m.role) {
                case Message::Role::System:    role = "system";    break;
                case Message::Role::User:      role = "user";      break;
                case Message::Role::Assistant: role = "assistant"; break;
                case Message::Role::Tool:      role = "user";      break;
            }
            messages.push_back({{"role", role}, {"content", m.content}});
        }
        rawr::InferenceResult r = client_.complete(messages, maxTokens_);
        if (!r.ok) throw std::runtime_error(r.error.empty() ? "backend failure" : r.error);
        return parseDecision(r.content);
    }

    Decision parseDecision(const std::string& content) {
        const std::string body = firstJsonObject(content);
        if (body.empty()) return Decision{};
        json obj;
        try { obj = json::parse(body); } catch (...) { return Decision{}; }
        if (!obj.is_object()) return Decision{};

        const std::string d = obj.value("decision", std::string());
        if (d == "final") {
            Decision out;
            out.kind = DecisionKind::Final;
            out.answer = obj.value("answer", std::string());
            return out;
        }
        if (d == "tool") {
            Decision out;
            out.kind = DecisionKind::Tool;
            out.tool.name = obj.value("tool", std::string());
            out.tool.path = obj.value("path", std::string("."));
            out.tool.query = obj.value("query", std::string());
            if (out.tool.name.empty() || out.tool.query.empty()) return Decision{};
            return out;
        }
        return Decision{};
    }

    rawr::InferenceClient& client_;
    int maxTokens_;
    bool repositoryQuestion_;
    int refused_ = 0;
};

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
                     "usage: sovereign_agent_live <workspace_root> <question> "
                     "[--endpoint PORT] [--model NAME] [--max-turns N]\n");
        return 2;
    }
    const std::string root = argv[1];
    std::string question;
    int port = 8080;
    std::string model;
    unsigned maxTurns = 8, maxToolCalls = 4;
    int maxTokens = 300;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--endpoint" && i + 1 < argc) port = std::atoi(argv[++i]);
        else if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--max-turns" && i + 1 < argc) maxTurns =
            static_cast<unsigned>(std::atoi(argv[++i]));
        else if (a == "--max-tokens" && i + 1 < argc) maxTokens = std::atoi(argv[++i]);
        else if (a.rfind("--", 0) != 0) question += (question.empty() ? "" : " ") + a;
    }
    if (question.empty()) {
        std::fprintf(stderr, "error: empty question\n");
        return 2;
    }

    rawr::InferenceClient client;
    client.setEndpoint(port);
    if (!model.empty()) client.setModel(model);
    if (!client.ping()) {
        std::fprintf(stderr, "ERROR: no local inference backend reachable on %d\n", port);
        return 3;
    }

    HostTools tools(root);
    LiveModelAdapter model_(client, maxTokens, isRepositoryQuestion(question));
    AgentRunner runner(model_, tools, maxTurns, maxToolCalls);

    AgentState state;
    Result r = runner.run(state, question);
    std::printf("%s\n", r.ok ? r.answer.c_str() : r.error.c_str());
    std::printf("%s", evidence_summary(r.state).c_str());
    // Host-gated exit: the run must have finished with a final answer AND every
    // executed receipt must be successful. Model prose cannot set this.
    bool allOk = r.ok;
    for (const auto& o : r.state.ledger)
        if (o.executed && !o.ok) allOk = false;
    std::printf("[host-verdict] ok=%d turn=%u executed_receipts=%zu\n",
                allOk ? 1 : 0, r.state.turns, r.state.ledger.size());
    return allOk ? 0 : 4;
}


