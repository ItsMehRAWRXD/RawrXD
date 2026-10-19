#pragma once
#include "Deep2DeepSeekRuntime.hpp"

namespace Deep2 { namespace dsv3 {
struct DualStickApi {
    uint64_t (*est)(unsigned,int,uint64_t);
    unsigned (*assign)(int,uint64_t,int);
    int (*resident)(int,int,unsigned*);
    int (*prefetch)(int,int,unsigned);
};
struct DualStickCtx { DualStickApi api; };
Hooks MakeDualStickHooks(DualStickCtx&);
}} 
