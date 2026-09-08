// certs/rawrxd_product_e2e_001.cpp — final umbrella (fail-closed seal aggregator)
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static bool Run(const char* exe, std::string& lastLine) {
    lastLine.clear();
#ifdef _WIN32
    std::string cmd = std::string("\"") + exe + "\"";
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p) return false;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) {
        lastLine = buf;
        fputs(buf, stdout);
    }
    int rc = _pclose(p);
    return rc == 0;
#else
    (void)exe;
    return false;
#endif
}

static bool LinePass(const std::string& s, const char* gate) {
    return s.find(std::string(gate) + "=PASS") != std::string::npos;
}

static bool FileContainsPass(const std::string& path, const char* key) {
    std::ifstream in(path);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string body = ss.str();
    if (body.empty()) return false;
    if (body.find(std::string(key) + "=FAIL") != std::string::npos)
        return false;
    return body.find(std::string(key) + "=PASS") != std::string::npos;
}

// Fail-closed: missing file, malformed body, or FAIL => not sealed.
static bool ReadGate(const char* gateKey, const char* evidDir) {
    const std::string root = "G:\\~dev\\rawrxd\\evidence\\";
    const std::string dir = root + evidDir;
    const char* names[] = {"GATE.txt", "GATE_STATUS.txt", "SEAL.txt",
                           "SEALS.txt"};
    for (const char* name : names) {
        if (FileContainsPass(dir + "\\" + name, gateKey)) return true;
    }
    // Aggregated unlock seals (legacy prior-seal store).
    if (FileContainsPass(root + "RAWRXD_PRODUCT_UNLOCK_15\\SEALS.txt", gateKey))
        return true;
    return false;
}

int main(int argc, char** argv) {
    const char* bin =
        argc > 1 ? argv[1] : "G:\\~dev\\rawrxd\\build-fd\\bin";
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_E2E_001",
                     nullptr);
#endif

    struct PriorSeal {
        const char* uid;
        const char* key;
        const char* evidDir;
    };
    // Prior seals — require disk evidence; never hardcode PASS.
    // U08 sealed: do not re-execute second_model exe if GATE_STATUS=PASS.
    const PriorSeal priors[] = {
        {"U01_STDOUT_CLEAN", "RAWRXD_STDOUT_CLEAN_001",
         "RAWRXD_STDOUT_CLEAN_001"},
        {"U02_CHAT_REPL", "RAWRXD_CHAT_REPL_001", "RAWRXD_CHAT_REPL_001"},
        {"U07_AUTO_LADDER", "RAWRXD_AUTO_LADDER_001",
         "RAWRXD_PRODUCT_UNLOCK_15"},
        {"U08_SECOND_MODEL_SEALED", "RAWRXD_SECOND_MODEL_001",
         "RAWRXD_SECOND_MODEL_001"},
        {"U09_EMBED_NORM_GUARD", "RAWRXD_EMBED_NORM_GUARD_001",
         "RAWRXD_EMBED_NORM_GUARD_001"},
        {"U10_NO_OLLAMA_CONTRACT", "RAWRXD_NO_OLLAMA_CONTRACT_001",
         "RAWRXD_NO_OLLAMA_CONTRACT_001"},
        {"U12_VWA_BOUNDED", "VWA_BOUNDED_K2_001", "VWA_BOUNDED_K2_001"},
        {"U15_PRODUCT_FRONTDOOR", "RAWRXD_PRODUCT_FRONTDOOR_001",
         "RAWRXD_PRODUCT_FRONTDOOR_001"},
        {"INTERSTELLAR_DEEP2", "RAWRXD_INTERSTELLAR_DEEP2_E2E_001",
         "RAWRXD_INTERSTELLAR_DEEP2_E2E_001"},
    };

    bool priorOk = true;
    for (const auto& p : priors) {
        const bool ok = ReadGate(p.key, p.evidDir);
        printf("%s=%s\n", p.uid, ok ? "PASS" : "FAIL");
        if (!ok) priorOk = false;
    }

    struct Gate {
        const char* id;
        const char* exe;
        bool required;
    };
    Gate gates[] = {
        {"U03_AGENT_PATCH_LIVE", "rawrxd_agent_workspace_live_001.exe", true},
        {"U04_AGENT_BUILD_LIVE", "rawrxd_agent_workspace_live_001.exe", true},
        {"U05_STEER_LIVE", "rawrxd_agent_steer_resume_001.exe", true},
        {"U06_RESUME_CHAT", "rawrxd_agent_steer_resume_001.exe", true},
        // U08 consumed via PriorSeal (RAWRXD_SECOND_MODEL_001) — do not reopen.
        {"U16_PRODUCT_LAYER", "rawrxd_product_layer_001.exe", true},
        {"U17_WIN32_SURFACE", "rawrxd_win32_editor_surface_001.exe", true},
        {"U18_RAWR_PIPE", "rawrxd_rawr_pipe_001.exe", true},
        {"U19_EDITOR_AGENT_E2E", "rawrxd_editor_agent_e2e_001.exe", true},
        {"U11_K2_PREFETCH_OVERLAP", "rawrxd_k2_product_e2e_001.exe", false},
        {"U12_BOUNDED_K2", "rawrxd_k2_product_e2e_001.exe", false},
        {"U13_K2_USEFUL_TPS", "rawrxd_k2_product_e2e_001.exe", false},
        {"U14_K2_SEMANTIC_COHERENCE", "rawrxd_k2_product_e2e_001.exe", false},
    };

    bool allReq = priorOk;
    bool k2 = false;
    bool ranK2 = false;
    for (const auto& g : gates) {
        if (ranK2 && std::string(g.exe) == "rawrxd_k2_product_e2e_001.exe") {
            printf("%s=%s\n", g.id, k2 ? "PASS" : "FAIL");
            if (g.required && !k2) allReq = false;
            continue;
        }
        std::string path = std::string(bin) + "\\" + g.exe;
        std::string last;
        bool ok = Run(path.c_str(), last);
        if (std::string(g.exe) == "rawrxd_k2_product_e2e_001.exe") {
            ranK2 = true;
            k2 = ok && LinePass(last, "RAWRXD_K2_PRODUCT_E2E_001");
            printf("%s=%s\n", g.id, k2 ? "PASS" : "FAIL");
            if (g.required && !k2) allReq = false;
            continue;
        }
        bool pass = ok;
        if (std::string(g.exe).find("workspace") != std::string::npos)
            pass = ok && LinePass(last, "RAWRXD_AGENT_WORKSPACE_LIVE_001");
        if (std::string(g.exe).find("steer") != std::string::npos) {
            pass = ok && LinePass(last, "RAWRXD_AGENT_STEER_RESUME_001");
            // Disk seal required for U05/U06 integrity.
            if (pass &&
                !ReadGate("RAWRXD_AGENT_STEER_RESUME_001",
                          "RAWRXD_AGENT_STEER_RESUME_001"))
                pass = false;
        }
        if (std::string(g.exe).find("second") != std::string::npos) {
            pass = ok && LinePass(last, "RAWRXD_SECOND_MODEL_001");
            if (pass &&
                !ReadGate("RAWRXD_SECOND_MODEL_001", "RAWRXD_SECOND_MODEL_001"))
                pass = false;
        }
        if (std::string(g.exe).find("product_layer") != std::string::npos)
            pass = ok && LinePass(last, "RAWRXD_PRODUCT_LAYER_001");
        if (std::string(g.exe).find("win32_editor") != std::string::npos)
            pass = ok && LinePass(last, "RAWRXD_WIN32_EDITOR_SURFACE_001");
        if (std::string(g.exe).find("rawr_pipe") != std::string::npos)
            pass = ok && LinePass(last, "RAWRXD_RAWR_PIPE_001");
        if (std::string(g.exe).find("editor_agent") != std::string::npos)
            pass = ok && LinePass(last, "RAWRXD_EDITOR_AGENT_E2E_001");
        printf("%s=%s\n", g.id, pass ? "PASS" : "FAIL");
        if (g.required && !pass) allReq = false;
    }

    const bool product = allReq;
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_E2E_001\\SEAL.txt");
    seal << "RAWRXD_PRODUCT_E2E_001=" << (product ? "PASS" : "FAIL") << "\n";
    seal << "PRIOR_SEALS=" << (priorOk ? "PASS" : "FAIL") << "\n";
    seal << "K2_PRODUCT_E2E=" << (k2 ? "PASS" : "FAIL") << "\n";
    puts(product ? "RAWRXD_PRODUCT_E2E_001=PASS"
                 : "RAWRXD_PRODUCT_E2E_001=FAIL");
    if (!priorOk)
        fprintf(stderr,
                "NOTE: prior seal ReadGate failed — umbrella fail-closed\n");
    if (!k2)
        fprintf(stderr,
                "NOTE: RAWRXD_K2_PRODUCT_E2E_001 not sealed — valuation jump "
                "pending\n");
    return product ? 0 : 1;
}
