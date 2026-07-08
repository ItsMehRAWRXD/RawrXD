// Stub implementation for vocab_resolver.cpp
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/vocab_resolver.h"
namespace RawrXD { namespace Core {
class VocabResolver::Impl {};
VocabResolver::VocabResolver() : pImpl(new Impl()) {}
VocabResolver::~VocabResolver() = default;
VocabResolver::VocabResolver(VocabResolver&&) noexcept = default;
VocabResolver& VocabResolver::operator=(VocabResolver&&) noexcept = default;
int VocabResolver::Resolve(const char*) { return 0; }
}} // namespace RawrXD::Core
