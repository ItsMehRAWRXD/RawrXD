#ifndef RAWRXD_CORE_TENSOR_OPS_H
#define RAWRXD_CORE_TENSOR_OPS_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT TensorOps {
public:
    TensorOps();
    ~TensorOps();
    TensorOps(const TensorOps&) = delete;
    TensorOps& operator=(const TensorOps&) = delete;
    TensorOps(TensorOps&&) noexcept;
    TensorOps& operator=(TensorOps&&) noexcept;
    bool Add();
    bool Multiply();
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_TENSOR_OPS_H
