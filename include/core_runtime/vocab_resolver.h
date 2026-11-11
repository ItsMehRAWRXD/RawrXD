#ifndef RAWRXD_CORE_VOCAB_RESOLVER_H
#define RAWRXD_CORE_VOCAB_RESOLVER_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT VocabResolver {
public:
    VocabResolver();
    ~VocabResolver();
    VocabResolver(const VocabResolver&) = delete;
    VocabResolver& operator=(const VocabResolver&) = delete;
    VocabResolver(VocabResolver&&) noexcept;
    VocabResolver& operator=(VocabResolver&&) noexcept;
    int Resolve(const char* token);
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_VOCAB_RESOLVER_H
