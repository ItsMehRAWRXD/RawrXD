// Stub implementation for gguf_tensor.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/gguf_tensor.h"
namespace RawrXD { namespace Core {
class GGUFTensor::Impl {};
GGUFTensor::GGUFTensor() : pImpl(new Impl()) {}
GGUFTensor::~GGUFTensor() = default;
GGUFTensor::GGUFTensor(GGUFTensor&&) noexcept = default;
GGUFTensor& GGUFTensor::operator=(GGUFTensor&&) noexcept = default;
size_t GGUFTensor::GetSize() const { return 0; }
}} // namespace RawrXD::Core
