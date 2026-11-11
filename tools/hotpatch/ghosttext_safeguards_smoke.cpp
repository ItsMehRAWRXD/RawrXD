// GhostText / routing / redact safeguard smoke. Standalone. PROMOTE=0.
#include "include/GhostTextSafeguardCore.hpp"
#include "include/LogRedact.hpp"
#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using rawrxd::hotpatch::AllocateGhostRequestId;
using rawrxd::hotpatch::BumpRoutingEpoch;
using rawrxd::hotpatch::CancelOutstandingGhost;
using rawrxd::hotpatch::CompleteGhostRequest;
using rawrxd::hotpatch::GhostResponseStillValid;
using rawrxd::hotpatch::GhostSafeguardState;
using rawrxd::hotpatch::RedactSecrets;

static int g_fail = 0;
static void Expect(bool ok, const char* name) {
    if (!ok) {
        std::printf("FAIL %s\n", name);
        ++g_fail;
    } else {
        std::printf("PASS %s\n", name);
    }
}

static void TestUniqueConcurrentIds() {
    GhostSafeguardState s;
    constexpr int N = 8;
    constexpr int PER = 256;
    std::vector<uint64_t> ids(static_cast<size_t>(N * PER));
    std::vector<std::thread> threads;
    for (int t = 0; t < N; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < PER; ++i) {
                ids[static_cast<size_t>(t * PER + i)] = AllocateGhostRequestId(s);
            }
        });
    }
    for (auto& th : threads) th.join();
    std::unordered_set<uint64_t> uniq(ids.begin(), ids.end());
    Expect(uniq.size() == ids.size(), "ghosttext_request_id_unique_concurrent");
}

static void TestModelSelectInvalidates() {
    GhostSafeguardState s;
    const uint64_t epoch0 = s.routingEpoch.load();
    const uint64_t id = AllocateGhostRequestId(s);
    const uint64_t cancel0 = s.cancelGeneration.load();
    Expect(GhostResponseStillValid(s, id, epoch0, cancel0), "outstanding_valid_before_model_change");
    BumpRoutingEpoch(s, "model-b");
    Expect(!GhostResponseStillValid(s, id, epoch0, cancel0), "stale_routing_rejected_after_model_select");
}

static void TestCancelInvalidates() {
    GhostSafeguardState s;
    const uint64_t epoch0 = s.routingEpoch.load();
    const uint64_t id = AllocateGhostRequestId(s);
    const uint64_t cancel0 = s.cancelGeneration.load();
    CancelOutstandingGhost(s);
    Expect(!GhostResponseStillValid(s, id, epoch0, cancel0), "cancel_invalidates_outstanding_ghost");
    const uint64_t id2 = AllocateGhostRequestId(s);
    const uint64_t epoch1 = s.routingEpoch.load();
    const uint64_t cancel1 = s.cancelGeneration.load();
    CompleteGhostRequest(s, id2);
    Expect(!GhostResponseStillValid(s, id2, epoch1, cancel1), "completed_request_not_outstanding");
}

static void TestRedact() {
    const std::string in =
        "Authorization: Bearer sk-live-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 api_key=supersecretvalue";
    const std::string out = RedactSecrets(in);
    Expect(out.find("sk-live") == std::string::npos, "redact_bearer_secret");
    Expect(out.find("supersecretvalue") == std::string::npos, "redact_api_key_value");
    Expect(out.find("[REDACTED]") != std::string::npos, "redact_marker_present");
}

int main() {
    TestUniqueConcurrentIds();
    TestModelSelectInvalidates();
    TestCancelInvalidates();
    TestRedact();
    std::printf("CERTIFIED=0 PROMOTE=0 FAIL_COUNT=%d\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
