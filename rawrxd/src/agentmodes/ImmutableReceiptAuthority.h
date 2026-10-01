// ImmutableReceiptAuthority.h — RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001
//
// A receipt at a fixed path is a mutable slot, not a record. The previous
// writer opened with "w" and truncated on begin, so any later run silently
// destroyed the evidence of an earlier retraction, failure or contamination.
// That is how a false PASS outlives the run that disproved it.
//
// This authority makes every run an immutable artifact:
//
//   receipts/<GATE>/runs/<UTC>_pid<n>_<sha12>.ini   CREATE_NEW, never replaced
//   receipts/<GATE>/latest.txt                       mutable pointer, allowed
//   receipts/<GATE>/index.jsonl                      append-only roll-up
//
// A commit whose destination already exists FAILS. Evidence cannot be lost to
// a later run.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace rawrxd { namespace imreceipt {

struct ReceiptRun {
    bool        success    = false;
    std::string gateName;
    std::string runId;
    std::string runPath;      // immutable artifact
    std::string latestPath;   // mutable pointer
    std::string indexPath;    // append-only
    std::string sha256;       // digest of the exact content written
    std::string verdict;
    bool        preexisted   = false;  // destination existed; commit refused
    bool        latestUpdated = false;
    bool        indexAppended = false;
    std::string error;
};

class ImmutableReceipt {
public:
    // `root` is the receipts tree; "receipts" relative to the working directory.
    explicit ImmutableReceipt(std::string gateName, std::string root = "receipts");

    void set(const std::string& key, const std::string& value);
    void setInt(const std::string& key, int64_t value);
    void setFloat(const std::string& key, double value);

    bool has(const std::string& key) const;
    std::string get(const std::string& key) const;

    // Serialize without writing. Useful for previewing and for tests.
    std::string serialize() const;

    // Write the artifact. Refuses to replace an existing run file.
    ReceiptRun commit(const std::string& verdict);

    // Commit with a caller-chosen run id. Still refuses any collision, so this
    // cannot be used to overwrite evidence either.
    ReceiptRun commitAs(const std::string& runId, const std::string& verdict);

    const std::string& gateName() const { return gateName_; }

    // Directory layout helpers, exposed so the CLI can report paths.
    static std::string runDir(const std::string& gateName, const std::string& root);
    static std::string latestPath(const std::string& gateName, const std::string& root);
    static std::string indexPath(const std::string& gateName, const std::string& root);

private:
    ReceiptRun writeLocked(const std::string& runId, const std::string& verdict);

    std::string gateName_;
    std::string root_;
    std::vector<std::pair<std::string, std::string>> fields_;
};

}} // namespace rawrxd::imreceipt
