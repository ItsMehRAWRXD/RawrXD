// Test-only driver: exercises the real OllamaBackend against a mock or real
// endpoint and prints the contract fields. Not part of the shipped build.
#include "agentic/OllamaBackend.h"

#include <cstdio>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: mock_driver <endpoint> <model>\n");
        return 2;
    }
    RawrXD::Agent::BackendConfig cfg;
    cfg.endpoint   = argv[1];
    cfg.model      = argv[2];
    cfg.max_tokens = 64;

    RawrXD::Agent::OllamaBackend backend;
    if (!backend.Initialize(cfg)) {
        std::printf("INIT_FAIL\n");
        return 1;
    }

    std::vector<RawrXD::Agent::ChatMessage> msgs;
    RawrXD::Agent::ChatMessage user;
    user.role = "user";
    user.content = "Reply with exactly: OK";
    msgs.push_back(user);

    const auto r = backend.ChatSync(msgs, nullptr);
    std::printf("OK=%d\n", r.success ? 1 : 0);
    std::printf("RESPONSE=[%s]\n", r.response.c_str());
    std::printf("REASONING=[%s]\n", r.reasoning.c_str());
    std::printf("ERROR=[%s]\n", r.error_message.c_str());
    backend.Shutdown();
    return 0;
}