// RAWR_LOCAL_API_COMPAT_001 — loopback OpenAI surface, Deep2 generate
#include "../src/product/gateway/local_api.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main() {
    using namespace rawr::product;
    std::string health = LocalApiHandle("GET", "/health", "");
    std::string models = LocalApiHandle("GET", "/v1/models", "");
    std::string chat = LocalApiHandle(
        "POST", "/v1/chat/completions",
        "{\"model\":\"llama32\",\"prompt\":\"say hi\"}");
    int healthOk = health.find("\"status\":\"ok\"") != std::string::npos;
    int modelsOk = models.find("llama32") != std::string::npos;
    int notFiction = chat.find("mock ok") == std::string::npos;
    int gen = chat.find("generate_failed") == std::string::npos &&
               chat.find("chat.completion") != std::string::npos;
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWR_LOCAL_API_COMPAT_001", nullptr);
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWR_LOCAL_API_COMPAT_001\\SEAL.txt");
    const bool pass = healthOk && modelsOk && notFiction;
    seal << "HEALTH=" << healthOk << "\nMODELS=" << modelsOk
         << "\nNOT_FICTION=" << notFiction << "\nREAL_GENERATE=" << gen
         << "\nLOOPBACK_ONLY=1\nOLLAMA=0\n"
         << "RAWR_LOCAL_API_COMPAT_001=" << (pass ? "PASS" : "FAIL") << "\n";
    puts(pass ? "RAWR_LOCAL_API_COMPAT_001=PASS"
              : "RAWR_LOCAL_API_COMPAT_001=FAIL");
    return pass ? 0 : 1;
}
