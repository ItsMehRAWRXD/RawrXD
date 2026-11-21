// Native (Qt-free) acceptance tests using a deterministic fixture process.
// Build: cl /nologo /std:c++17 /EHsc /W4 /MT native_acceptance_test.cpp
// Requires: fixture path as argv[1], or RAWRXD_ACCEPTANCE_FIXTURE env var.

#include "src/agent/native_acceptance.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace rawrxd;

static int g_fail = 0;

static void Expect(const char* name, bool cond, const std::string& detail = {})
{
    if (cond) return;
    std::printf("FAIL: %s%s%s\n", name, detail.empty() ? "" : " :: ", detail.c_str());
    ++g_fail;
}

int main(int argc, char** argv)
{
    std::string fixture;
    if (argc > 1) fixture = argv[1];
    else if (const char* env = std::getenv("RAWRXD_ACCEPTANCE_FIXTURE")) fixture = env;
    if (fixture.empty()) {
        std::printf("usage: native_acceptance_test.exe <fixture.exe>\n");
        return 2;
    }

    AcceptanceCriteria markerCriteria;
    markerCriteria.expectedExit = 0;
    markerCriteria.stderrMustContain = "[BRIDGE_GEN]";

    // 1. exit 0, no marker -> rejected
    {
        auto r = RunWithAcceptance(fixture, {"silent"}, {}, 30000, markerCriteria);
        Expect("silent rejected", !r.accepted, r.firstFailure);
        Expect("silent exit 0", r.exitCode == 0);
        Expect("silent names the marker",
               r.firstFailure == "missing_stderr_marker=[BRIDGE_GEN]", r.firstFailure);
    }

    // 2. exit 0 with marker -> accepted
    {
        auto r = RunWithAcceptance(fixture, {"marker"}, {}, 30000, markerCriteria);
        Expect("marker accepted", r.accepted, r.firstFailure);
        Expect("marker exit 0", r.exitCode == 0);
    }

    // 3. exit 7 -> rejected with the real code
    {
        AcceptanceCriteria c;
        c.expectedExit = 0;
        auto r = RunWithAcceptance(fixture, {"failure"}, {}, 30000, c);
        Expect("failure rejected", !r.accepted, r.firstFailure);
        Expect("failure exit reported",
               r.firstFailure.find("7") != std::string::npos, r.firstFailure);
    }

    if (g_fail == 0) {
        std::printf("NATIVE_ACCEPTANCE_TESTS=PASS\n");
        return 0;
    }
    std::printf("NATIVE_ACCEPTANCE_TESTS=FAIL count=%d\n", g_fail);
    return 1;
}