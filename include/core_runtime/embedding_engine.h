#ifndef RAWRXD_CORE_EMBEDDING_ENGINE_H
#define RAWRXD_CORE_EMBEDDING_ENGINE_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT EmbeddingEngine {
public:
    EmbeddingEngine();
    ~EmbeddingEngine();
    EmbeddingEngine(const EmbeddingEngine&) = delete;
    EmbeddingEngine& operator=(const EmbeddingEngine&) = delete;
    EmbeddingEngine(EmbeddingEngine&&) noexcept;
    EmbeddingEngine& operator=(EmbeddingEngine&&) noexcept;
    bool Initialize();
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_EMBEDDING_ENGINE_H
