#include "Deep2B57ContextKernel.hpp"

namespace Deep2 {

B57ContextPlan B57ContextKernel::make(const B57ContextShape& s) noexcept {
    B57ContextPlan p{};
    p.tokenTile = s.context >= 262144 ? 512u :
                  (s.context >= 65536 ? 256u :
                  (s.context >= 16384 ? 128u : 64u));
    p.headTile = s.heads >= 64 ? 4u : (s.heads >= 32 ? 2u : 1u);
    p.rankTile = s.kvRank >= 512 ? 128u : 64u;
    p.kvPageTokens = s.context >= 131072 ? 1024u :
                     (s.context >= 32768 ? 512u : 256u);
    p.pagedKv = s.context >= 32768;
    p.slidingWindowPreferred = !s.useMLA && s.context >= 131072;
    p.flashStreaming = true;
    return p;
}

}
