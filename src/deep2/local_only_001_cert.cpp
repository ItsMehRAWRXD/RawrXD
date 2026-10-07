// ============================================================================
// local_only_001_cert.cpp — LOCAL_ONLY_001 runtime proof
// ============================================================================
// Pass when:
//   1) 127.0.0.1:11434 is unreachable
//   2) Deep2/GGUF generate succeeds (no Ollama client)
//   3) Forbidden-URL / fail-closed diagnostics are hard (not stub chat text)
// ============================================================================

#include "Deep2Engine.h"
#include "../agentic/LocalOnlyPolicy.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

using namespace Deep2;

struct Check {
    const char* id = nullptr;
    bool pass = false;
    std::string detail;
};

static std::vector<Check> g_checks;

static void record(const char* id, bool pass, const std::string& detail) {
    g_checks.push_back(Check{id, pass, detail});
    std::printf("[%s] %s — %s\n", pass ? "PASS" : "FAIL", id, detail.c_str());
}

static bool probePort11434Reachable() {
#ifdef _WIN32
    HINTERNET session = WinHttpOpen(L"LOCAL_ONLY_001/1.0",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;
    WinHttpSetTimeouts(session, 500, 500, 500, 500);
    HINTERNET conn = WinHttpConnect(session, L"127.0.0.1", 11434, 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        return false;
    }
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", L"/api/tags", nullptr,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    bool ok = false;
    if (req) {
        if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(req, nullptr)) {
            ok = true;
        }
        WinHttpCloseHandle(req);
    }
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return ok;
#else
    return false;
#endif
}

static bool ollamaProcessPresent() {
#ifdef _WIN32
    // Best-effort: CreateToolhelp32Snapshot would be heavier; use tasklist pipe.
    FILE* pipe = _popen("tasklist /FI \"IMAGENAME eq ollama.exe\" /NH 2>NUL", "r");
    if (!pipe) return false;
    char buf[512];
    std::string out;
    while (fgets(buf, sizeof(buf), pipe)) out += buf;
    _pclose(pipe);
    return out.find("ollama.exe") != std::string::npos;
#else
    return false;
#endif
}

static std::string resolveModelPath(int argc, char** argv) {
    if (argc >= 2 && argv[1] && argv[1][0]) return argv[1];
    const char* env = std::getenv("RAWRXD_LOCAL_MODEL");
    if (env && env[0]) return env;
    const char* candidates[] = {
        "F:\\~dev\\tinyllama_fresh.gguf",
        "F:\\~dev\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
        "D:\\rawrxd\\models\\tinyllama.gguf",
        nullptr};
    for (int i = 0; candidates[i]; ++i) {
        std::ifstream f(candidates[i], std::ios::binary);
        if (f.good()) return candidates[i];
    }
    return {};
}

int main(int argc, char** argv) {
    std::printf("LOCAL_ONLY_001 cert\n");
    std::printf("RAWRXD_LOCAL_ONLY=%d\n", RAWRXD_LOCAL_ONLY);
    std::printf("INFERENCE_BACKEND=Deep2/GGUF\n");

    record("POLICY_ENABLED", RawrXD::LocalOnly::kEnabled,
           RawrXD::LocalOnly::kEnabled ? "compile-time local-only ON" : "OFF");

    record("SANITIZE_11434",
           RawrXD::LocalOnly::sanitizeBaseUrl("http://127.0.0.1:11434").empty(),
           "forbidden URL cleared to empty");

    record("ALLOW_OLLAMA_HTTP",
           !RawrXD::LocalOnly::allowOllamaHttpClient(),
           "Ollama HTTP client construction forbidden");

    const bool ollamaPresent = ollamaProcessPresent();
    record("OLLAMA_EXE_ABSENT", !ollamaPresent,
           ollamaPresent ? "ollama.exe is running (gate wants ABSENT)" : "ollama.exe not listed");

    const bool portUp = probePort11434Reachable();
    record("PORT_11434_UNREACHABLE", !portUp,
           portUp ? "127.0.0.1:11434 answered (FAIL)" : "127.0.0.1:11434 unreachable");

    const std::string hard = RawrXD::LocalOnly::kHardDiagnostic;
    const bool looksLikeStub =
        hard.find("placeholder") != std::string::npos ||
        hard.find("Welcome") != std::string::npos ||
        hard.find("[Fallback Stub]") != std::string::npos;
    record("FAIL_CLOSED_DIAGNOSTIC",
           hard.find("LOCAL_ONLY_001") != std::string::npos &&
               hard.find("FAIL_CLOSED") != std::string::npos && !looksLikeStub,
           hard);

    std::string modelPath = resolveModelPath(argc, argv);
    if (modelPath.empty()) {
        record("DEEP2_GENERATE", false, "no GGUF found (pass path via argv[1] or RAWRXD_LOCAL_MODEL)");
    } else {
        std::printf("MODEL=%s\n", modelPath.c_str());
        Deep2Engine engine;
        std::string loadErr;
        const bool loaded = engine.loadModel(modelPath);
        if (!loaded) {
            record("DEEP2_GENERATE", false, "Deep2Engine::loadModel failed");
        } else {
            std::string text = engine.generateText("Say ping.", 16);
            const bool ok = !text.empty() &&
                            text.find("LOCAL_ONLY_001") == std::string::npos &&
                            text.find("ollama") == std::string::npos &&
                            text.find("11434") == std::string::npos;
            record("DEEP2_GENERATE", ok,
                   ok ? ("generated " + std::to_string(text.size()) + " chars via Deep2/GGUF")
                      : ("empty or contaminated response: " + text.substr(0, 120)));
            engine.unloadModel();
        }
    }

    int failed = 0;
    for (const auto& c : g_checks) {
        if (!c.pass) ++failed;
    }

    std::printf("\nSUMMARY pass=%zu fail=%d\n", g_checks.size() - failed, failed);
    std::printf("OLLAMA_CLIENT_PRESENT=NO (cert does not construct AgentOllamaClient)\n");
    std::printf("NETWORK_FALLBACK=FORBIDDEN\n");
    std::printf("VERDICT=%s\n", failed == 0 ? "PASS" : "FAIL");
    return failed == 0 ? 0 : 1;
}
