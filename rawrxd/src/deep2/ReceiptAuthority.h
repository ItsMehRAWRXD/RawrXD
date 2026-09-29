// ReceiptAuthority.h — RAWRXD_RECEIPT_AUTHORITY_001
// Named receipt writer. Every gate writes machine-readable receipts
// instead of relying on stderr.
//
// Direct call sites:
//   rawrxd::receipt::writeKeyValue(path, key, value)
//   rawrxd::receipt::beginGate(path, gateName)
//   rawrxd::receipt::endGate(path, verdict)
#pragma once
#include <string>
#include <cstdint>

namespace rawrxd { namespace receipt {

void writeKeyValue(const std::string& path, const std::string& key, const std::string& value);
void writeKeyValueInt(const std::string& path, const std::string& key, int64_t value);
void writeKeyValueFloat(const std::string& path, const std::string& key, double value);
void beginGate(const std::string& path, const std::string& gateName);
void endGate(const std::string& path, const std::string& verdict);

}} // namespace rawrxd::receipt