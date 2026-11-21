// Mock tests for the Ollama health classifier.
// Build: cl /nologo /std:c++17 /EHsc /W4 /MT ollama_health_test.cpp

#include "src/agent/ollama_health.hpp"

#include <cstdio>

using namespace rawrxd;

static int g_fail = 0;

static void Expect(const char* name, bool cond)
{
    if (!cond) {
        std::printf("FAIL: %s\n", name);
        ++g_fail;
    }
}

int main()
{
    // Healthy: 200 + valid body
    {
        OllamaProbeFacts f; f.connected = true; f.httpStatus = 200; f.validTagsJson = true;
        Expect("200 valid -> available", ClassifyOllamaProbe(f) == OllamaHealth::Available);
    }
    // Connection refused
    {
        OllamaProbeFacts f;  // connected=false, status=0
        Expect("refused -> unavailable", ClassifyOllamaProbe(f) == OllamaHealth::Unavailable);
    }
    // Timeout
    {
        OllamaProbeFacts f; f.connected = true; f.timedOut = true;
        Expect("timeout -> unavailable", ClassifyOllamaProbe(f) == OllamaHealth::Unavailable);
    }
    // Malformed JSON
    {
        OllamaProbeFacts f; f.connected = true; f.httpStatus = 200; f.validTagsJson = false;
        Expect("malformed -> degraded", ClassifyOllamaProbe(f) == OllamaHealth::Degraded);
    }
    // Unexpected HTTP status
    {
        OllamaProbeFacts f; f.connected = true; f.httpStatus = 500; f.validTagsJson = false;
        Expect("http 500 -> degraded", ClassifyOllamaProbe(f) == OllamaHealth::Degraded);
    }
    // A 200 with invalid body must never be Available
    {
        OllamaProbeFacts f; f.connected = true; f.httpStatus = 200; f.validTagsJson = false;
        Expect("200 invalid not available",
               ClassifyOllamaProbe(f) != OllamaHealth::Available);
    }
    // Health string mapping
    {
        Expect("available string",
               std::string(ToString(OllamaHealth::Available)) == "available");
        Expect("degraded string",
               std::string(ToString(OllamaHealth::Degraded)) == "degraded");
    }

    if (g_fail == 0) {
        std::printf("OLLAMA_HEALTH_TESTS=PASS\n");
        return 0;
    }
    std::printf("OLLAMA_HEALTH_TESTS=FAIL count=%d\n", g_fail);
    return 1;
}