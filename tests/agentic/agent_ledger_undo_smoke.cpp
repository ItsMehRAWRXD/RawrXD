// agent_ledger_undo_smoke.cpp — Gap 7 + 10 translation-unit proof
// 1) AgentEditHistory: write → record before/after → undo → prior bytes
// 2) AgentSession + PersistentTaskBacklog: create/update round-trip to disk
// CERTIFIED=0 PROMOTE=0 — NOT_RUN != PASS; this smoke is RUNTIME_REACHED for
// the ledger/undo units only (not full Win32IDE exe E2E).
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include "../../src/agentic/AgentEditHistory.h"
#include "../../src/agentic/AgentSession.h"
#include "../../src/agentic/PersistentTaskBacklog.h"

namespace fs = std::filesystem;
using RawrXD::Agent::AgentEditHistory;
using RawrXD::Agent::AgentEditSnapshot;
using RawrXD::Agent::AgentSession;
using RawrXD::Agent::PersistentTask;
using RawrXD::Agent::PersistentTaskBacklog;
using RawrXD::Agent::ReadFileBytes;
using RawrXD::Agent::TaskStatus;
using RawrXD::Agent::WriteFileBytes;

static int failures = 0;

static void expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) ++failures;
}

static int testUndoRestore(const fs::path& root) {
    const fs::path file = root / "undo_target.txt";
    const std::string prior = "PRIOR_BYTES_V1\n";
    const std::string after = "AFTER_AGENT_EDIT_V2\n";
    expect(WriteFileBytes(file.string(), prior), "write_prior");
    expect(WriteFileBytes(file.string(), after), "write_after");

    AgentEditHistory hist;
    AgentEditSnapshot snap;
    snap.filePath = file.string();
    snap.oldContent = prior;
    snap.newContent = after;
    hist.push(snap);
    expect(hist.size() == 1, "history_recorded");
    expect(hist.undoLast(), "undo_last");
    std::string restored;
    expect(ReadFileBytes(file.string(), restored), "read_restored");
    expect(restored == prior, "undo_restored_prior_bytes");
    expect(hist.size() == 0, "history_popped");
    return 0;
}

static int testLedgerRoundTrip(const fs::path& root) {
    const fs::path ledgerPath = root / "ledger" / "agent_session.json";
    const fs::path tasksDir = root / "tasks";

    AgentSession session(ledgerPath.string());
    session.SetTaskId("smoke-task-001");
    session.SetModelIdentity("smoke/model");
    session.SetWorkspaceRoot(root.string());
    session.AppendUserMessage("smoke turn");
    session.RecordAgentTurn();
    session.RecordFileModified((root / "undo_target.txt").string());
    session.SetTermination(RawrXD::Agent::TerminationReason::ModelCompleted, 0);
    session.SetVerdict("SMOKE");
    session.Flush();
    expect(fs::exists(ledgerPath), "session_ledger_on_disk");

    AgentSession loaded(ledgerPath.string());
    expect(loaded.LoadFromDisk(), "session_load_from_disk");
    expect(loaded.TaskId() == "smoke-task-001", "session_task_id_roundtrip");
    expect(loaded.AgentTurnCount() >= 1, "session_turns_roundtrip");
    expect(loaded.FileModifiedCount() >= 1, "session_files_roundtrip");

    PersistentTaskBacklog backlog(tasksDir.string());
    PersistentTask t;
    t.title = "smoke-ledger";
    t.description = "roundtrip";
    t.status = TaskStatus::Pending;
    const std::string id = backlog.AddTask(t);
    expect(!id.empty(), "backlog_add");
    backlog.MarkTaskStarted(id);
    backlog.MarkTaskCompleted(id, "smoke_ok");
    backlog.Flush();

    PersistentTaskBacklog reloaded(tasksDir.string());
    auto got = reloaded.GetTask(id);
    expect(got.has_value(), "backlog_reload_get");
    if (got) {
        expect(got->status == TaskStatus::Completed, "backlog_status_completed");
        expect(got->final_result == "smoke_ok", "backlog_result_roundtrip");
    }
    return 0;
}

int main() {
    const fs::path root = fs::temp_directory_path() / "rawrxd_agent_ledger_undo_smoke";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root, ec);

    testUndoRestore(root);
    testLedgerRoundTrip(root);

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("SOURCE_WIRED=1\n");
    std::printf("RUNTIME_REACHED=%s\n", failures == 0 ? "1" : "0");
    std::printf("CERTIFIED=0\n");
    std::printf("PROMOTE=0\n");
    fs::remove_all(root, ec);
    return failures == 0 ? 0 : 1;
}
