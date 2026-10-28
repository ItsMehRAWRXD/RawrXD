#include "AgentProduct.hpp"
#include "AgentSession.hpp"
#include "../product/gateway/product_deep2_infer.hpp"
#include "../subagent_core.h"
#include <sstream>

static std::string Field(const std::string& body, const char* key) {
    const std::string pat = std::string("\"") + key + "\"";
    auto p = body.find(pat);
    if (p == std::string::npos) return {};
    p = body.find(':', p);
    auto a = p == std::string::npos ? std::string::npos : body.find('"', p + 1);
    auto b = a == std::string::npos ? std::string::npos : body.find('"', a + 1);
    if (a == std::string::npos || b == std::string::npos) return {};
    return body.substr(a + 1, b - a - 1);
}

static std::string Esc(const std::string& s) {
    std::string o;
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back((char)c); }
        else if (c == '\n') o += "\\n";
        else if (c >= 32) o.push_back((char)c);
        if (o.size() > 8000) break;
    }
    return o;
}

static std::string ProductInfer(void*, const std::string& prompt, int maxTokens) {
    std::string out;
    rawr::ProductDeep2InferStream(prompt.c_str(), maxTokens,
        [](const std::string&) { return true; }, &out);
    return out;
}

static std::string Spawn(void* ctx, const char* d, const char* p) {
    return static_cast<SubAgentManager*>(ctx)->spawnSubAgent(
        "agent", d ? d : "", p ? p : "");
}
static bool Wait(void* ctx, const char* id, int ms) {
    return static_cast<SubAgentManager*>(ctx)->waitForSubAgent(id ? id : "", ms);
}
static std::string Result(void* ctx, const char* id) {
    return static_cast<SubAgentManager*>(ctx)->getSubAgentResult(id ? id : "");
}
static const char* StateOf(void* ctx, const char* id) {
    static char buf[32];
    const SubAgent* agent =
        static_cast<SubAgentManager*>(ctx)->getSubAgent(id ? id : "");
    std::string s = agent ? agent->stateString() : "missing";
    strncpy_s(buf, s.c_str(), _TRUNCATE);
    return buf;
}

static void Bind(SubAgentManager* mgr) {
    if (mgr) AgentBindWorker(mgr, Spawn, Wait, Result, StateOf);
}

void AgentBindManager(void* manager) { Bind(static_cast<SubAgentManager*>(manager)); }

int AgentHttpRun(const std::string& body, bool modelReady, void* subAgentMgr,
                 std::string* outJson) {
    std::string sj; int sc = AgentSessionAdmit(body, &sj);
    if (sc) { if (outJson) *outJson = sj; return sc; }
    std::string prompt = Field(body, "prompt");
    if (prompt.empty()) prompt = Field(body, "content");
    if (prompt.empty()) {
        if (outJson) *outJson = "{\"error\":\"missing_prompt\"}";
        return 400;
    }
    if (!modelReady) {
        if (outJson) *outJson = "{\"error\":\"model_not_loaded\"}";
        return 503;
    }
    Bind(static_cast<SubAgentManager*>(subAgentMgr));
    AgentRunResult run = AgentRunLoop(prompt, 8, 2048, nullptr, ProductInfer);
    std::ostringstream json;
    json << "{\"agent_session\":true," << AgentSessionCountersJson()
         << ",\"iterations\":" << run.iterations
         << ",\"tool_calls\":" << run.toolCalls
         << ",\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\""
         << Esc(run.text) << "\"}}],\"tool_log\":\"" << Esc(run.toolLog) << "\"}";
    if (outJson) *outJson = json.str();
    return 200;
}
