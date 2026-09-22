#pragma once
#include <cstdint>

namespace Deep2 {

struct B57ContextShape {
    uint32_t context = 0;
    uint32_t heads = 0;
    uint32_t kvHeads = 0;
    uint32_t headDim = 0;
    uint32_t kvRank = 0;
    bool useMLA = false;
};

struct B57ContextPlan {
    uint32_t tokenTile = 64;
    uint32_t headTile = 1;
    uint32_t rankTile = 64;
    uint32_t kvPageTokens = 256;
    bool slidingWindowPreferred = false;
    bool flashStreaming = true;
    bool pagedKv = false;
};

class B57ContextKernel {
public:
    static B57ContextPlan make(const B57ContextShape&) noexcept;
};

}
