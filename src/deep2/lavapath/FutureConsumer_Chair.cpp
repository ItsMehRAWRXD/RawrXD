/* FutureConsumer_Chair.cpp — ready bit + continuation resume (chair+gen). */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"

namespace Deep2 {
namespace future {

int BindContinuation(ChairId chair, uint32_t /*expectedGen*/, ContinuationFn fn,
                     void* ctx) {
    Chair* c = ChairAt(chair);
    if (!c) return 0;
    std::lock_guard<std::mutex> lock(detail::Mu());
    c->continuation = fn;
    c->continuationCtx = ctx;
    return 1;
}

int SignalChairReady(ChairId chair, uint32_t readyGen) {
    Chair* c = ChairAt(chair);
    if (!c) return 0;
    ContinuationFn fn = nullptr;
    void* ctx = nullptr;
    {
        std::lock_guard<std::mutex> lock(detail::Mu());
        c->readyGeneration = readyGen;
        if (c->continuation) {
            fn = c->continuation;
            ctx = c->continuationCtx;
            c->continuation = nullptr;
            c->continuationCtx = nullptr;
        }
    }
    if (fn) fn(ctx);
    return 1;
}

int TryResumeChair(ChairId chair, uint32_t expectedGen) {
    Chair* c = ChairAt(chair);
    if (!c) return 0;
    ContinuationFn fn = nullptr;
    void* ctx = nullptr;
    {
        std::lock_guard<std::mutex> lock(detail::Mu());
        if (c->readyGeneration != expectedGen) {
            detail::Exec().staleGenerationReads++;
            return 0;
        }
        fn = c->continuation;
        ctx = c->continuationCtx;
        if (fn) {
            c->continuation = nullptr;
            c->continuationCtx = nullptr;
        }
    }
    if (fn) fn(ctx);
    return 1;
}

} // namespace future
} // namespace Deep2
