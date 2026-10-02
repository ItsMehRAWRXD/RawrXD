// ============================================================================
// CheckpointRollbackAuthority.h
//   RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001
//
// Purpose
//   An autonomous IDE must be able to answer, after a crash, exactly what an
//   agent was doing and exactly how to undo it. "Rollback == git reset" is not
//   that answer: git knows the index and HEAD, it does not know
//     - the agent plan that was in flight,
//     - the pre-modification bytes of files (including untracked and new ones),
//     - which commands were executed and what they returned,
//     - which tool calls produced which results,
//     - the diagnostics and model/context state at that moment,
//     - the working-tree identity the work started from.
//
// On-disk contract (all paths are absolute on disk, utf-8 in the journal)
//   <workspace>\.rawrxd\ckpt\blobs\<sha256>            content-addressed blobs
//   <workspace>\.rawrxd\ckpt\journal\<txid>.jrnl       append-only journal
//   <workspace>\.rawrxd\ckpt\recovery\<txid>.txt       recovery receipt
//
// Durability contract
//   - Blobs are written with FILE_FLAG_WRITE_THROUGH + FlushFileBuffers and are
//     published with MoveFileExW(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH).
//   - A journal record is appended and flushed AFTER the blob it references is
//     durable, so a recoverable record never points at a missing blob.
//   - Every record line carries a CRC32. A torn trailing line (the classic
//     power-loss artifact) fails CRC and is discarded, which is exactly the
//     behaviour that makes an interrupted write safe.
//   - File publishes go through a temp file plus atomic rename, so a crash
//     mid-write can never leave a truncated target file behind.
//
// The SHA-256 implementation below is intentionally self-contained. The
// existing rawrxd::cert::sha256* helpers live in src/agentmodes/RawrCertAuthority.cpp,
// which is compiled only into the `rawr` target; linking it from InferenceEngine
// would duplicate the symbol in every target that already has it.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace ckpt {

// SHA-256 (FIPS 180-4), lowercase hex. Exposed for receipts that must hash
// state captured by this authority.
std::string sha256Hex(const void* data, std::size_t len);
std::string sha256Hex(const std::string& data);
std::string sha256FileHex(const std::string& path);

// The identity of the working tree a transaction was opened against. Every
// field is measured from bytes on disk; nothing here is asserted.
struct WorkingTreeIdentity {
    bool gitPresent = false;          // a .git entry exists at the workspace root
    std::string gitDir;               // resolved .git directory (worktree aware)
    std::string headRef;              // e.g. refs/heads/main
    std::string headSha;              // resolved commit, empty when unborn
    std::string indexSha256;          // sha256 over the raw .git/index bytes
    std::string treeSha256;           // sha256 over sorted (relpath, content-sha256) tuples
    std::uint64_t fileCount = 0;      // files under the root, .git/.rawrxd excluded
    std::uint64_t totalBytes = 0;
    std::uint64_t largeFilesHashedBySize = 0;  // files above the content-hash cap
    std::string identitySha256;       // sha256 over every field above
};

struct TransactionSpec {
    std::string workspaceRoot;  // absolute; the .rawrxd\ckpt tree is created here
    std::string intent;         // short label, e.g. "agent multi-file edit"
    std::string plan;           // the agent plan in flight
    std::string modelContext;   // model/context state snapshot
    std::string diagnostics;    // diagnostics snapshot
};

// Counters are incremented at the site of the effect, never predicted.
// RAWRXD_RECOVERY_REPORT_FORWARD_001
// Transaction::LastRecovery() returns this by value and is declared before the
// definition below, so the type must be at least declared here. Without this
// the build failed with C3646 'LastRecovery': unknown override specifier.
struct RecoveryReport;

struct MeasuredCounters {

    std::uint64_t journalRecords = 0;
    std::uint64_t journalFlushes = 0;
    std::uint64_t blobWrites = 0;
    std::uint64_t blobFlushes = 0;
    std::uint64_t atomicPublishes = 0;
    std::uint64_t fileWrites = 0;
    std::uint64_t fileDeletes = 0;
    std::uint64_t crcFailures = 0;
    std::uint64_t faultsInjected = 0;
};

// Process-wide active transaction. There is exactly one writer per IDE process
// (RAWRXD_SINGLE_WRITER_AUTHORITY_001), so one active transaction is the correct
// cardinality; a second Begin is refused rather than silently nesting.
class Transaction {
public:
    static bool Begin(const TransactionSpec& spec, std::string* outTxId, std::string* outError);
    static bool Active();
    static std::string ActiveTxId();
    static std::string ActiveWorkspaceRoot();

    // The transactional write used by every agentic file mutation. When a
    // transaction is active it captures before-state, publishes atomically and
    // records after-state. With no transaction it still publishes atomically,
    // so a crash can never leave a half-written file.
    static bool WriteFile(const std::string& absPath, const std::string& content, std::string* outError);
    // Same, for callers that already hold a canonical wide path. Prefer this
    // over the utf-8 overload when the path came from std::filesystem::path,
    // whose narrow string is in the active code page, not utf-8.
    static bool WriteFileW(const std::wstring& absPathW, const std::string& content,
                           std::string* outError);

    static bool RecordCommand(const std::string& command, int exitCode, const std::string& stdoutText,
                              const std::string& stderrText, std::uint64_t elapsedMicros);
    static bool RecordToolResult(const std::string& tool, const std::string& paramsText, bool success,
                                 const std::string& output, const std::string& error,
                                 std::uint64_t elapsedMicros);

    // Marks the transaction complete. After Commit the journal is closed and a
    // later recovery pass will not touch the files it recorded.
    static bool Commit(std::string* outError);
    // Rolls back immediately, in-process, using the same code path recovery uses.
    static bool Rollback(std::string* outError);
    // The measured report from the most recent Rollback() in this process.
    // Rollback() reports success as a bool, and a bool cannot distinguish
    // "restored 4 files and verified 4 hashes" from "restored nothing", so a
    // caller that has to certify the rollback reads this instead.
    //
    // RecoveryReport is DEFINED below this point, so it needs a forward
    // declaration for a by-value return to be legal here. A declaration only
    // needs an incomplete type; the definition needs the complete one, which it
    // has further down.
    static RecoveryReport LastRecovery();

    // RAWRXD_GIT_TRANSACTION_AUTHORITY_001 / G7
    //
    // A transaction that stages a file and is then rolled back leaves that file
    // BOTH reverted in content AND still staged: the journal restores file
    // bytes, and nothing has ever restored the index. That is an inconsistent
    // state, because the next `git status` reports a staged modification of a
    // file whose content is the pre-transaction content.
    //
    // Captures the repository index as a tree object, once per transaction,
    // before the first mutating git operation. Rollback then issues
    // `git read-tree <tree>` so the index is exactly as it was found.
    //
    // Returns false and fills outError when the workspace is not a git
    // repository, or when the index cannot be written as a tree (an unmerged
    // index has no tree object). Callers must read false as "no baseline was
    // recorded", never as success.
    static bool RecordGitIndexBaseline(std::string* outTree, std::string* outError);

    static WorkingTreeIdentity CaptureIdentity(const std::string& workspaceRoot);
    static MeasuredCounters Counters();
};

// Result of a startup recovery pass. Every field is measured during the pass.
struct RecoveryReport {
    bool invoked = false;
    std::string workspaceRoot;
    std::uint32_t journalsScanned = 0;
    std::uint32_t closedTransactions = 0;        // COMMIT already present
    std::uint32_t incompleteTransactions = 0;   // no COMMIT: rolled back
    std::uint32_t filesRestored = 0;             // pre-existing files rewritten
    std::uint32_t filesDeleted = 0;              // files created by the transaction
    std::uint32_t filesVerified = 0;             // post-restore sha256 matches before-state
    std::uint32_t filesFailed = 0;
    std::uint32_t tornRecordsDiscarded = 0;
    std::uint32_t missingBlobs = 0;
    std::uint64_t fsyncCalls = 0;
    // RAWRXD_GIT_TRANSACTION_AUTHORITY_001 / G7. A restored index is reported
    // separately from restored files, and a FAILED index restore is its own
    // counter rather than an entry in filesFailed: the file bytes are correct
    // and the repository is still wrong, and an operator told only "recovery
    // succeeded" would never look at the index.
    std::uint32_t gitIndexRestored = 0;
    std::uint32_t gitIndexFailed = 0;
    std::string gitIndexTree;    // the tree object the index was restored to
    std::string gitIndexError;   // measured git output when the restore failed
    std::vector<std::string> recoveredTxIds;
    std::vector<std::string> failedPaths;
    std::string receiptPath;
    std::string identityBeforeSha256;  // working-tree identity at pass start
    std::string identityAfterSha256;   // working-tree identity at pass end

    // FAIL when any file could not be restored or verified. Derived, never set.
    // A failed index restore makes the repository wrong even when every file
    // byte is correct, so it is NOT folded into filesFailed: it has to be
    // separately visible, and it fails this predicate.
    bool AllRestored() const { return invoked && filesFailed == 0 && gitIndexFailed == 0; }
};

// Scans <workspace>\.rawrxd\ckpt\journal, rolls back every transaction that has
// no COMMIT record, verifies each restored file against its recorded
// before-state hash, and writes one receipt per recovered transaction.
// This is the function the IDE calls at startup.
RecoveryReport RecoverWorkspace(const std::string& workspaceRoot, bool writeReceipt);

// Crash injection for the recovery proof. Enabled only when RAWRXD_CKPT_FAULT is
// set to one of:
//   crash_before_write:<n>  die immediately before publishing file n of the tx
//   crash_torn:<n>          publish only half of file n's bytes to the TARGET
//                           path non-atomically, then die (torn-write case)
//   crash_after:<n>         die after file n completed
// The process dies via TerminateProcess: no destructors, no atexit handlers,
// no buffered-stream flushes. That is the point.
bool FaultInjectionEnabled();
std::string FaultInjectionDescription();

}  // namespace ckpt
}  // namespace rawrxd