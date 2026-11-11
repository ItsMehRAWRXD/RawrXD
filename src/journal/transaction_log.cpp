// Stub implementation for transaction_log.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/transaction_log.h"
namespace RawrXD { namespace Core {
class TransactionLog::Impl {};
TransactionLog::TransactionLog() : pImpl(new Impl()) {}
TransactionLog::~TransactionLog() = default;
TransactionLog::TransactionLog(TransactionLog&&) noexcept = default;
TransactionLog& TransactionLog::operator=(TransactionLog&&) noexcept = default;
bool TransactionLog::Append(const void*, size_t) { return true; }
}} // namespace RawrXD::Core
