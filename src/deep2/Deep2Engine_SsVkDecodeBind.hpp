#pragma once
/* Deep2Engine_SsVkDecodeBind — product D2DecodeBindOps → real Deep2Engine.
 * GATE=DEEP2_ENGINE_SSVK_DECODE_BIND_001  PROMOTE=0 */
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace Deep2 {

class Deep2Engine;

struct SsVkDecodeBindUser {
    Deep2Engine* engine = nullptr;
    std::vector<float> hidden;
    std::vector<float> logits;
    std::string utf8Scratch;
    int lastInputToken = 0;
    int promptSeeded = 0;
    uint64_t snapHostFwd = 0;
    uint64_t snapHostMat = 0;
    uint64_t snapCpuExpand = 0;
    uint64_t snapQ2kPacked = 0;
    uint64_t persistentPrepares = 0;
    uint32_t commandRebuildsThisToken = 0;
};

/* Fill D2DecodeBindOps (C ABI) for d2_decode_bind_open. */
void SsVkDecodeBindFillOps(struct D2DecodeBindOps* ops, SsVkDecodeBindUser* user);

} // namespace Deep2
