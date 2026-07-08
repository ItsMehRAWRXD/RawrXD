// Stub implementation for vector_store.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/vector_store.h"
namespace RawrXD { namespace Core {
class VectorStore::Impl {};
VectorStore::VectorStore() : pImpl(new Impl()) {}
VectorStore::~VectorStore() = default;
VectorStore::VectorStore(VectorStore&&) noexcept = default;
VectorStore& VectorStore::operator=(VectorStore&&) noexcept = default;
bool VectorStore::Add(const float*, size_t) { return true; }
}} // namespace RawrXD::Core
