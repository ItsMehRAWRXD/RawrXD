#ifndef RAWRXD_CORE_TRANSACTION_LOG_H
#define RAWRXD_CORE_TRANSACTION_LOG_H
#include "core_export.h"
#include <memory>
#include <cstddef>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT TransactionLog {
public:
    TransactionLog();
    ~TransactionLog();
    TransactionLog(const TransactionLog&) = delete;
    TransactionLog& operator=(const TransactionLog&) = delete;
    TransactionLog(TransactionLog&&) noexcept;
    TransactionLog& operator=(TransactionLog&&) noexcept;
    bool Append(const void* data, size_t size);
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_TRANSACTION_LOG_H
