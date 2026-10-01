// BATCH_0 — RAWRXD_SINGLE_WRITER_AUTHORITY_001 gate harness
//
// Every predicate below is MEASURED by performing the action and observing the
// real refusal returned by WriterLeaseAuthority. Nothing is asserted from a
// comment, and nothing about the real repository is modified: every git command
// runs against a throwaway scratch repo under TEMP.
#include "agentmodes/WriterLeaseAuthority.h"
#include "agentmodes/RawrCertAuthority.h"

#include <windows.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace rawrxd;

// ---------------------------------------------------------------- utilities

static int run(const std::string& cmd) {
    FILE* p = _popen((cmd + " >nul 2>&1").c_str(), "r");
    if (!p) return -1;
    char buf[512];
    while (std::fgets(buf, sizeof buf, p)) {}
    return _pclose(p);
}

static std::string capture(const std::string& cmd) {
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p) return {};
    std::string out;
    char buf[512];
    while (std::fgets(buf, sizeof buf, p)) out += buf;
    _pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

static void writeFile(const fs::path& p, const std::string& body) {
    fs::create_directories(p.parent_path());
    std::ofstream o(p, std::ios::binary | std::ios::trunc);
    o << body;
}

// Creation FILETIME of an arbitrary process; 0 when it cannot be read.
static uint64_t startTimeOf(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    FILETIME c{}, e{}, k{}, u{};
    const BOOL ok = GetProcessTimes(h, &c, &e, &k, &u);
    CloseHandle(h);
    if (!ok) return 0;
    return (static_cast<uint64_t>(c.dwHighDateTime) << 32) | c.dwLowDateTime;
}

// A live, foreign process we can name in a lease. Held open for the test.
struct ForeignProcess {
    HANDLE h = nullptr;
    DWORD  pid = 0;
    uint64_t start = 0;
    bool started() const { return h != nullptr && h != INVALID_HANDLE_VALUE; }
    void stop() { if (started()) { TerminateProcess(h, 0); WaitForSingleObject(h, 2000); CloseHandle(h); h = nullptr; } }
};

static bool startForeign(ForeignProcess& fp) {
    STARTUPINFOA si{}; si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    std::string cmd = "cmd /c ping -n 120 127.0.0.1 >nul";
    if (!CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
    fp.h = pi.hProcess;
    fp.pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    fp.start = startTimeOf(fp.pid);
    return fp.start != 0;
}

// The verdict is a pure function of the six measured predicates. Keeping it a
// function is what makes the mutation probe in main() meaningful.
static const char* computeVerdict(bool c1, bool c2, bool c3, bool c4, bool c5, bool c6) {
    return (c1 && c2 && c3 && c4 && c5 && c6) ? "PASS" : "FAIL";
}

struct Report {
    std::vector<std::string> lines;
    void add(const std::string& k, const std::string& v) { lines.push_back(k + "=" + v); }
};

int main(int argc, char** argv) {
    const fs::path scratch = (argc > 1) ? fs::path(argv[1])
                                         : fs::path("C:/Windows/Temp") / "rawr_lease_scratch";
    const fs::path receipt = (argc > 2) ? fs::path(argv[2]) : fs::path("RECEIPT.txt");

    std::error_code ec;
    fs::remove_all(scratch, ec);
    fs::create_directories(scratch, ec);
    const std::string root = scratch.string();

    // Scratch repo with one initial commit, so HEAD is a real value.
    run("git init -q \"" + root + "\"");
    run("git -C \"" + root + "\" config user.email gate@rawrxd.local");
    run("git -C \"" + root + "\" config user.name  \"rawrxd gate\"");
    run("git -C \"" + root + "\" config commit.gpgsign false");
    writeFile(scratch / "seed.txt", "seed\n");
    run("git -C \"" + root + "\" add seed.txt");
    run("git -C \"" + root + "\" commit -q -m seed");
    const std::string H0 = capture("git -C \"" + root + "\" rev-parse HEAD");

    Report r;
    r.add("GATE", "RAWRXD_SINGLE_WRITER_AUTHORITY_001");
    r.add("BATCH", "BATCH_0");
    r.add("SCRATCH_REPO", root);
    r.add("SHA256_SELFTEST", cert::sha256SelfTest() ? "PASS" : "FAIL");
    r.add("H0", H0);

    ForeignProcess fp;
    const bool foreignUp = startForeign(fp);
    r.add("FOREIGN_LIVE_PROCESS_STARTED", foreignUp ? "1" : "0");
    r.add("FOREIGN_LIVE_PID", std::to_string(fp.pid));

    // ---- C1: a second writer cannot acquire an exclusively-created lease ----
    lease::AcquireResult a1 = lease::acquire(root, H0, 600);
    r.add("C1_FIRST_ACQUIRE_OUTCOME", std::to_string((int)a1.outcome));

    // (a) plain second acquisition while a live lease exists
    lease::AcquireResult a2 = lease::acquire(root, H0, 600);
    const bool c1a = (a2.outcome == lease::AcquireOutcome::HeldByLiveProcess);
    r.add("C1_SECOND_ACQUIRE_OUTCOME", std::to_string((int)a2.outcome));
    r.add("C1_SECOND_ACQUIRE_DETAIL", a2.detail);

    // (b) a genuinely foreign live owner replaces the record
    bool c1b = false;
    if (foreignUp) {
        lease::LeaseRecord foreign;
        foreign.leaseId = "foreign-1"; foreign.ownerPid = fp.pid;
        foreign.ownerStartTime = fp.start; foreign.nonce = "foreign-nonce";
        foreign.expectedHead = H0; foreign.host = "foreign-host";
        foreign.acquiredUtc = a1.record.acquiredUtc; foreign.expiresUtc = a1.record.expiresUtc;
        foreign.ttlSeconds = 600;
        writeFile(fs::path(lease::leasePath(root)), lease::serialize(foreign));
        lease::AcquireResult a3 = lease::acquire(root, H0, 600);
        c1b = (a3.outcome == lease::AcquireOutcome::HeldByLiveProcess);
        r.add("C1_FOREIGN_LIVE_ACQUIRE_OUTCOME", std::to_string((int)a3.outcome));
        r.add("C1_FOREIGN_LIVE_ACQUIRE_DETAIL", a3.detail);
    }
    const bool C1 = c1a && c1b;
    r.add("C1_FOREIGN_PROCESS_ALIVE_MEASURED", foreignUp ? std::to_string(lease::processAlive(fp.pid, fp.start) ? 1 : 0) : "0");

    // ---- C2: commit with no lease present is refused ----
    {
        std::error_code e2; fs::remove(fs::path(lease::leasePath(root)), e2);
        lease::CommitCheck c = lease::checkCommit(root, a1.record);
        r.add("C2_NO_LEASE_REFUSAL", std::to_string((int)c.refusal));
        r.add("C2_NO_LEASE_DETAIL", c.detail);
        // CommitRefusal::NoLease == 1
        r.add("SECOND_WRITER_ACQUIRE_BLOCKED", C1 ? "1" : "0");
        r.add("COMMIT_WITHOUT_LEASE_BLOCKED",
              (c.refusal == lease::CommitRefusal::NoLease && !c.ok) ? "1" : "0");
    }
    std::error_code e2b; fs::remove(fs::path(lease::leasePath(root)), e2b);
    const bool C2 = [&] {
        lease::CommitCheck c = lease::checkCommit(root, a1.record);
        return c.refusal == lease::CommitRefusal::NoLease && !c.ok;
    }();

    // ---- C3: HEAD moving under the lease blocks the next commit ----
    lease::AcquireResult a4 = lease::acquire(root, H0, 600);
    writeFile(scratch / "move1.txt", "moved\n");
    run("git -C \"" + root + "\" add move1.txt");
    run("git -C \"" + root + "\" commit -q -m \"foreign commit\"");
    const std::string H1 = capture("git -C \"" + root + "\" rev-parse HEAD");
    r.add("H1", H1);
    r.add("HEAD_MOVED", (H0 != H1) ? "1" : "0");
    lease::CommitCheck c3 = lease::checkCommit(root, a4.record);
    r.add("C3_HEAD_MOVED_REFUSAL", std::to_string((int)c3.refusal));
    r.add("C3_HEAD_MOVED_DETAIL", c3.detail);
    const bool C3 = (c3.refusal == lease::CommitRefusal::HeadMoved && !c3.ok);
    r.add("COMMIT_AFTER_HEAD_MOVED_BLOCKED", C3 ? "1" : "0");
    r.add("ACQUIRE_AFTER_HEAD_MOVED", std::to_string((int)a4.outcome));

    // ---- C4: a staged path outside the authorized scope is refused ----
    // The C3 lease is still held, so it must be released first; otherwise
    // acquire() hands back the old record and every check short-circuits at
    // HeadMoved before the scope test is ever reached.
    r.add("C3_LEASE_RELEASED", lease::release(root, a4.record) ? "1" : "0");
    lease::AcquireResult a5 = lease::acquire(root, H1, 600);
    r.add("C4_ACQUIRE_OUTCOME", std::to_string((int)a5.outcome));
    r.add("C4_LEASE_EXPECTED_HEAD", a5.record.expectedHead);
    lease::setAuthorizedPaths({ "authorized.txt" });
    run("git -C \"" + root + "\" reset -q");
    writeFile(scratch / "authorized.txt", "ok\n");
    writeFile(scratch / "sneaky.txt", "not approved\n");
    run("git -C \"" + root + "\" add authorized.txt sneaky.txt");
    lease::CommitCheck c4 = lease::checkCommit(root, a5.record);
    r.add("C4_STAGED_COUNT", std::to_string(c4.stagedCount));
    r.add("C4_SCOPE_REFUSAL", std::to_string((int)c4.refusal));
    r.add("C4_SCOPE_DETAIL", c4.detail);
    const bool C4refuse = (c4.refusal == lease::CommitRefusal::StagedScopeExpanded && !c4.ok);

    // Positive control: with only authorized paths staged, the check must pass.
    // Without this, C4 could be a check that refuses everything.
    run("git -C \"" + root + "\" reset -q");
    run("git -C \"" + root + "\" add authorized.txt");
    lease::CommitCheck c4ok = lease::checkCommit(root, a5.record);
    r.add("C4_CONTROL_OK", c4ok.ok ? "1" : "0");
    r.add("C4_CONTROL_REFUSAL", std::to_string((int)c4ok.refusal));
    const bool C4 = C4refuse && c4ok.ok;
    r.add("UNAUTHORIZED_STAGED_PATH_BLOCKED", C4 ? "1" : "0");

    // ---- C5: a foreign lease is never released on our say-so ----
    bool c5 = false;
    if (foreignUp) {
        lease::LeaseRecord foreign;
        foreign.leaseId = "foreign-2"; foreign.ownerPid = fp.pid;
        foreign.ownerStartTime = fp.start; foreign.nonce = "foreign-nonce-2";
        foreign.expectedHead = H1; foreign.host = "foreign-host";
        foreign.acquiredUtc = a5.record.acquiredUtc; foreign.expiresUtc = a5.record.expiresUtc;
        foreign.ttlSeconds = 600;
        writeFile(fs::path(lease::leasePath(root)), lease::serialize(foreign));

        const bool released = lease::release(root, a5.record);   // not ours
        lease::LeaseRecord after;
        const bool stillThere = lease::load(root, after);
        c5 = (!released && stillThere && after.nonce == "foreign-nonce-2");
        r.add("C5_RELEASE_RETURNED_TRUE", released ? "1" : "0");
        r.add("C5_LEASE_STILL_PRESENT", stillThere ? "1" : "0");
        r.add("C5_LEASE_OWNER_PID_AFTER", std::to_string(after.ownerPid));
        r.add("C5_FOREIGN_OWNER_PID", std::to_string(fp.pid));
    }
    r.add("FOREIGN_LEASE_RELEASE_BLOCKED", c5 ? "1" : "0");

    // ---- C6: a lease whose owner is provably dead is recoverable ----
    // Spawn a process we can kill ourselves, read its creation time while it is
    // still running, then terminate it. Every intermediate fact is recorded so
    // a failure distinguishes "harness did not produce a dead pid" from
    // "processAlive() misreports a terminated process as alive".
    STARTUPINFOA dsi{}; dsi.cb = sizeof dsi;
    PROCESS_INFORMATION dpi{};
    std::string dcmd = "cmd /c ping -n 60 127.0.0.1 >nul";   // long-lived on purpose
    uint32_t deadPid = 0; uint64_t deadStart = 0; bool deadProven = false;
    DWORD waitResult = 0xFFFFFFFF; DWORD exitCode = 0xDEADBEEF;
    bool openAfterExit = false, getExitOk = false;
    if (CreateProcessA(nullptr, const_cast<char*>(dcmd.c_str()), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &dsi, &dpi)) {
        deadPid = dpi.dwProcessId;
        deadStart = startTimeOf(deadPid);          // read while alive
        const bool aliveAtRead = (deadStart != 0) && lease::processAlive(deadPid, deadStart);
        r.add("C6_PID_ALIVE_AT_START_TIME_READ", aliveAtRead ? "1" : "0");
        TerminateProcess(dpi.hProcess, 1);
        waitResult = WaitForSingleObject(dpi.hProcess, 5000);
        // Windows keeps a process object openable while any handle remains, so
        // close ours before asking whether the pid is still alive.
        CloseHandle(dpi.hThread);
        CloseHandle(dpi.hProcess);
        deadProven = aliveAtRead && (waitResult == WAIT_OBJECT_0);

        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, deadPid);
        openAfterExit = (h != nullptr);
        if (h) { getExitOk = GetExitCodeProcess(h, &exitCode) != 0; CloseHandle(h); }
    }
    r.add("C6_TERMINATED_WAIT_RESULT", std::to_string(waitResult));
    r.add("C6_OPENPROCESS_AFTER_EXIT_SUCCEEDED", openAfterExit ? "1" : "0");
    r.add("C6_GETEXITCODE_OK", getExitOk ? "1" : "0");
    r.add("C6_EXIT_CODE", std::to_string(exitCode));
    const bool processAliveReportsDead = lease::processAlive(deadPid, deadStart);
    r.add("C6_PROCESSALIVE_REPORTS_ALIVE", processAliveReportsDead ? "1" : "0");
    const bool deadIsDead = deadProven && !processAliveReportsDead;
    r.add("C6_DEAD_PID", std::to_string(deadPid));
    r.add("C6_DEAD_PID_CONFIRMED_DEAD", deadIsDead ? "1" : "0");

    bool c6 = false;
    if (deadIsDead) {
        lease::LeaseRecord stale;
        stale.leaseId = "stale-1"; stale.ownerPid = deadPid;
        stale.ownerStartTime = deadStart; stale.nonce = "stale-nonce";
        stale.expectedHead = H1; stale.host = "stale-host";
        stale.acquiredUtc = a5.record.acquiredUtc; stale.expiresUtc = a5.record.expiresUtc;
        stale.ttlSeconds = 600;
        writeFile(fs::path(lease::leasePath(root)), lease::serialize(stale));

        lease::AcquireResult a6 = lease::acquire(root, H1, 600);
        lease::LeaseRecord now;
        lease::load(root, now);
        r.add("C6_RECOVERY_OUTCOME", std::to_string((int)a6.outcome));
        r.add("C6_RECOVERY_DETAIL", a6.detail);
        r.add("C6_NEW_OWNER_PID", std::to_string(now.ownerPid));
        c6 = (a6.outcome == lease::AcquireOutcome::StaleRecovered && now.ownerPid != deadPid);
    }
    r.add("STALE_LEASE_RECOVERY_TESTED", c6 ? "1" : "0");

    fp.stop();

    // ---- verdict provenance ----
    // The measured verdict below comes from the six real predicates. Proving it
    // is not hardcoded means proving computeVerdict() is not a constant
    // function, so the probe drives that function directly with forced inputs.
    // Probing the measured outcome instead would be vacuous: while the gate is
    // failing, no mutation can change the result.
    const bool all[6] = { C1, C2, C3, C4, c5, c6 };
    const char* base = computeVerdict(all[0], all[1], all[2], all[3], all[4], all[5]);

    const char* vAll  = computeVerdict(true, true, true, true, true, true);
    const char* vNone = computeVerdict(false, false, false, false, false, false);
    int dependent = 0;
    for (int i = 0; i < 6; ++i) {
        bool m[6] = { true, true, true, true, true, true };
        m[i] = false;
        if (std::string(computeVerdict(m[0], m[1], m[2], m[3], m[4], m[5])) != vAll) ++dependent;
    }
    const bool distinguishes = (std::string(vAll) != vNone);
    const bool derived = (dependent == 6) && distinguishes;
    r.add("PROBE_ALL_TRUE", vAll);
    r.add("PROBE_ALL_FALSE", vNone);
    r.add("VERDICT_PREDICATES_DEPENDENT", std::to_string(dependent));
    r.add("VERDICT_DISTINGUISHES_INPUTS", distinguishes ? "1" : "0");
    r.add("VERDICT_DERIVED_FROM_CHECKS", derived ? "1" : "0");
    r.add("HARDCODED_VERDICT", derived ? "0" : "1");

    r.add("RAWRXD_SINGLE_WRITER_AUTHORITY_001", base);

    std::string out;
    for (const auto& l : r.lines) out += l + "\n";
    fs::create_directories(receipt.parent_path());
    std::ofstream o(receipt, std::ios::binary | std::ios::trunc);
    o << out;
    std::fputs(out.c_str(), stdout);
    return std::string(base) == "PASS" ? 0 : 1;
}
