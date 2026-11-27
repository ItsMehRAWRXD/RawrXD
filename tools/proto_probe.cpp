// proto_probe.cpp — RAWRXD_NATIVE_MODEL_PROTOCOL_COMPLIANCE_129
// One structured tool exchange per model; reports which response channels the
// model actually uses. Isolates protocol compliance from task completion.
#include "OllamaExecutor.hpp"
#include <cstdio>
#include <string>
#include <vector>

static const char* Schema() {
    return "[{\"type\":\"function\",\"function\":{\"name\":\"list\",\"description\":\"list workspace\",\"parameters\":{\"type\":\"object\",\"properties\":{}}}}]";
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::vector<std::string> models;
    for (int i = 1; i < argc; ++i) models.push_back(argv[i]);
    if (models.empty()) models = {"gpt-oss:20b","deepseek-coder-v2:16b","qwen3:8b","nemotron-3.5-lightning:30b"};
    for (auto& m : models) {
        std::string body = "{\"model\":\"" + m + "\",\"stream\":false,\"keep_alive\":\"10m\",\"options\":{\"temperature\":0,\"num_predict\":512},\"tools\":";
        body += Schema();
        body += ",\"messages\":[{\"role\":\"system\",\"content\":\"You are a tool-using agent. Output exactly one native tool call, no prose.\"},{\"role\":\"user\",\"content\":\"Call the list tool now.\"}]}";
        bool ok = false;
        std::string r = rawrxd::ollama::HttpPost(L"127.0.0.1", 11434, L"/api/chat", body, ok);
        if (!ok || r.empty()) { std::printf("MODEL=%s TRANSPORT_FAIL\n", m.c_str()); continue; }
        bool hasTool = r.find("\"tool_calls\"") != std::string::npos && r.find("\"name\"") != std::string::npos;
        bool hasThink = (r.find("\"thinking\"") != std::string::npos || r.find("reasoning_content") != std::string::npos);
        std::string content = rawrxd::ollama::JsonStr(r, "\"content\"");
        std::string doneReason = rawrxd::ollama::JsonStr(r, "\"done_reason\"");
        std::printf("MODEL=%s TOOL_CALLS=%d CONTENT_LEN=%zu THINKING=%d DONE_REASON=%s\n",
            m.c_str(), (int)hasTool, content.size(), (int)hasThink, doneReason.c_str());
    }
    return 0;
}