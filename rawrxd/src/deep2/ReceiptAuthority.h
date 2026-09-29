// ReceiptAuthority.h — RAWRXD_RECEIPT_AUTHORITY_001
// RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001
//
// Named receipt writer with immutable per-run discipline.
// Each gate writes to: receipts/<GATE_NAME>/runs/<UTC>_<PID>_<RUN_ID>.ini
// Also maintains: receipts/<GATE_NAME>/latest.txt (mutable pointer)
//                 receipts/<GATE_NAME>/index.jsonl (append-only)
//
// Rules:
//   - Run receipt path is CREATE_NEW only (fail if exists)
//   - latest.txt may be overwritten
//   - index.jsonl is append-only
//   - Receipt SHA256 computed after writing
//   - Fixed-path receipt writes DISALLOWED except explicit latest pointers
//
// Direct call sites:
//   rawrxd::receipt::beginImmutableGate(gateName) -> returns run path
//   rawrxd::receipt::writeKeyValue(runPath, key, value)
//   rawrxd::receipt::endImmutableGate(runPath, verdict)
//   rawrxd::receipt::writeKeyValue(path, key, value)  // legacy fixed-path
//   rawrxd::receipt::beginGate(path, gateName)         // legacy fixed-path
//   rawrxd::receipt::endGate(path, verdict)            // legacy fixed-path
#pragma once
#include <string>
#include <cstdint>

namespace rawrxd { namespace receipt {

// === Immutable per-run receipt API ===

// Begin a new immutable receipt for a gate.
// Creates receipts/<gateName>/runs/<UTC>_<PID>_<runId>.ini (CREATE_NEW).
// Updates receipts/<gateName>/latest.txt to point to the run path.
// Appends to receipts/<gateName>/index.jsonl.
// Returns the run path on success, empty string on failure.
std::string beginImmutableGate(const std::string& gateName);

// Write a key=value line to an immutable receipt (append to run path).
void writeImmutableKeyValue(const std::string& runPath, const std::string& key, const std::string& value);
void writeImmutableKeyValueInt(const std::string& runPath, const std::string& key, int64_t value);
void writeImmutableKeyValueFloat(const std::string& runPath, const std::string& key, double value);

// Finalize an immutable receipt: compute SHA256, write RECEIPT_SHA256 line,
// update latest.txt, append to index.jsonl.
// Returns the SHA256 of the receipt file.
std::string endImmutableGate(const std::string& runPath, const std::string& verdict);

// Get the SHA256 of a receipt file.
std::string sha256File(const std::string& path);

// === Legacy fixed-path API (still available but not for new gates) ===

void writeKeyValue(const std::string& path, const std::string& key, const std::string& value);
void writeKeyValueInt(const std::string& path, const std::string& key, int64_t value);
void writeKeyValueFloat(const std::string& path, const std::string& key, double value);
void beginGate(const std::string& path, const std::string& gateName);
void endGate(const std::string& path, const std::string& verdict);

}} // namespace rawrxd::receipt