// W8LifecycleAuthority.h — RAWRXD_W8_LIFECYCLE_AUTHORITY_001
//
// MIGRATION_BATCH_1 — adopted ReceiptAuthority immutable per-run API.
//   writes to receipts/<gateName>/runs/<UTC>_<PID>_<RUN>.ini
//   updates   receipts/<gateName>/latest.txt
//   appends   receipts/<gateName>/index.jsonl
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace lifecycle {

// Stable gate identifier used for the receipts/<gateName>/ directory.
static constexpr const char* W8_GATE_NAME = "W8_HEADLESS_IDLE_LIFECYCLE_001";

void beginStayAliveCert(uint32_t durationSec);
void recordShutdownRequest(const char* reason);
void allowShutdown();

// Write the W8 lifecycle receipt using the immutable API.
// `gateName` must be a stable identifier (e.g. W8_GATE_NAME).
// Returns the run path on success, empty string on failure.
// Verdict is derived from measured fields (timer expired, target vs actual).
std::string writeW8Receipt(const std::string& gateName);

}} // namespace rawrxd::lifecycle