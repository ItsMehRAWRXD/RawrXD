// lease_tool — acquire / inspect / release the RAWRXD_STUB_RECONCILIATION_001
// writer lease on the real repository. The gate in single_writer_gate.cpp runs
// against a scratch repo; this tool is what actually takes the lease before any
// source mutation is allowed.
#include "agentmodes/WriterLeaseAuthority.h"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace rawrxd;

static std::string capture(const std::string& cmd) {
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p) return {};
    std::string out; char buf[512];
    while (std::fgets(buf, sizeof buf, p)) out += buf;
    _pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

static const char* outcomeName(lease::AcquireOutcome o) {
    switch (o) {
        case lease::AcquireOutcome::Acquired:          return "ACQUIRED";
        case lease::AcquireOutcome::StaleRecovered:    return "STALE_RECOVERED";
        case lease::AcquireOutcome::HeldByLiveProcess: return "HELD_BY_LIVE_PROCESS";
        case lease::AcquireOutcome::HeldUnreadable:    return "HELD_UNREADABLE";
        default:                                       return "FAILED";
    }
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: lease_tool <repoRoot> <acquire|show|release> [ttlSeconds]\n");
        return 2;
    }
    const std::string root = argv[1];
    const std::string mode = argv[2];
    const int ttl = (argc > 3) ? std::atoi(argv[3]) : 28800;   // 8h; batches run long

    if (mode == "acquire") {
        const std::string head = capture("git -C \"" + root + "\" rev-parse HEAD");
        lease::AcquireResult r = lease::acquire(root, head, ttl);
        std::printf("ACQUIRE_OUTCOME=%s\n", outcomeName(r.outcome));
        std::printf("ACQUIRE_DETAIL=%s\n", r.detail.c_str());
        std::printf("LEASE_OWNER_PID=%u\n", r.record.ownerPid);
        std::printf("LEASE_OWNER_PROCESS_START_TIME=%llu\n",
                    (unsigned long long)r.record.ownerStartTime);
        std::printf("LEASE_HOST=%s\n", r.record.host.c_str());
        std::printf("LEASE_START_HEAD=%s\n", r.record.expectedHead.c_str());
        std::printf("LEASE_SCOPE=RAWRXD_STUB_RECONCILIATION_001\n");
        std::printf("LEASE_STARTED_UTC=%s\n", r.record.acquiredUtc.c_str());
        std::printf("LEASE_EXPIRES_UTC=%s\n", r.record.expiresUtc.c_str());
        std::printf("LEASE_NONCE=%s\n", r.record.nonce.c_str());
        std::printf("LEASE_FILE=%s\n", lease::leasePath(root).c_str());
        return (r.outcome == lease::AcquireOutcome::Acquired ||
                r.outcome == lease::AcquireOutcome::StaleRecovered) ? 0 : 1;
    }

    if (mode == "show") {
        lease::LeaseRecord rec;
        if (!lease::load(root, rec)) { std::printf("LEASE_PRESENT=0\n"); return 1; }
        std::printf("LEASE_PRESENT=1\n");
        std::printf("LEASE_OWNER_PID=%u\n", rec.ownerPid);
        std::printf("LEASE_OWNER_PROCESS_START_TIME=%llu\n", (unsigned long long)rec.ownerStartTime);
        std::printf("LEASE_START_HEAD=%s\n", rec.expectedHead.c_str());
        std::printf("LEASE_HOST=%s\n", rec.host.c_str());
        std::printf("LEASE_STARTED_UTC=%s\n", rec.acquiredUtc.c_str());
        std::printf("LEASE_EXPIRES_UTC=%s\n", rec.expiresUtc.c_str());
        std::printf("OWNER_PROCESS_ALIVE=%d\n", lease::processAlive(rec.ownerPid, rec.ownerStartTime) ? 1 : 0);
        std::printf("CURRENT_HEAD=%s\n", capture("git -C \"" + root + "\" rev-parse HEAD").c_str());
        return 0;
    }

    if (mode == "hold") {
        // A lease is only a mutex while its owner is alive. A short-lived tool
        // that acquires and exits leaves a lease that any contender may legally
        // recover as stale, which is no lock at all. `hold` therefore stays
        // resident until a stop file appears, and releases on the way out.
        if (argc < 4) { std::fprintf(stderr, "hold needs <ttlSeconds> <stopFile>\n"); return 2; }
        const std::string stopFile = argv[4];
        const std::string head = capture("git -C \"" + root + "\" rev-parse HEAD");
        lease::AcquireResult r = lease::acquire(root, head, ttl);
        std::printf("ACQUIRE_OUTCOME=%s\n", outcomeName(r.outcome));
        std::printf("LEASE_OWNER_PID=%u\n", r.record.ownerPid);
        std::printf("LEASE_OWNER_PROCESS_START_TIME=%llu\n",
                    (unsigned long long)r.record.ownerStartTime);
        std::printf("LEASE_HOST=%s\n", r.record.host.c_str());
        std::printf("LEASE_START_HEAD=%s\n", r.record.expectedHead.c_str());
        std::printf("LEASE_SCOPE=RAWRXD_STUB_RECONCILIATION_001\n");
        std::printf("LEASE_STARTED_UTC=%s\n", r.record.acquiredUtc.c_str());
        std::printf("LEASE_EXPIRES_UTC=%s\n", r.record.expiresUtc.c_str());
        std::printf("LEASE_NONCE=%s\n", r.record.nonce.c_str());
        std::fflush(stdout);
        if (r.outcome != lease::AcquireOutcome::Acquired &&
            r.outcome != lease::AcquireOutcome::StaleRecovered) return 1;
        // Stay resident so the recorded owner pid is a real, live process.
        while (!fs::exists(stopFile)) { Sleep(2000); }
        const bool rel = lease::release(root, r.record);
        std::printf("RELEASE=%s\n", rel ? "OK" : "REFUSED");
        std::fflush(stdout);
        return rel ? 0 : 1;
    }

    if (mode == "release") {
        lease::LeaseRecord rec;
        if (!lease::load(root, rec)) { std::printf("RELEASE=NO_LEASE\n"); return 1; }
        const bool ok = lease::release(root, rec);
        std::printf("RELEASE=%s\n", ok ? "OK" : "REFUSED");
        return ok ? 0 : 1;
    }

    std::fprintf(stderr, "unknown mode %s\n", mode.c_str());
    return 2;
}
