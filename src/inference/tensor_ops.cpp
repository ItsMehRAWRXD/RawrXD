// Stub implementation for tensor_ops.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/tensor_ops.h"
namespace RawrXD { namespace Core {
class TensorOps::Impl {};
TensorOps::TensorOps() : pImpl(new Impl()) {}
TensorOps::~TensorOps() = default;
TensorOps::TensorOps(TensorOps&&) noexcept = default;
TensorOps& TensorOps::operator=(TensorOps&&) noexcept = default;
bool TensorOps::Add() { return true; }
bool TensorOps::Multiply() { return true; }
}} // namespace RawrXD::Core
