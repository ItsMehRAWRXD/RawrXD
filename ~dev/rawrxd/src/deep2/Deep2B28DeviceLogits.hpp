#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

struct B28LogitsShape {
    uint32_t hidden = 0;
    uint32_t vocab = 0;
    uint32_t quantBits = 4;
    bool tiedEmbedding = false;
};

struct B28DeviceLogitsPlan {
    uint32_t vocab0Begin = 0;
    uint32_t vocab0End = 0;
    uint32_t vocab1Begin = 0;
    uint32_t vocab1End = 0;
    uint32_t workgroup = 256;
    uint32_t vectorWidth = 8;
    bool fuseFinalNorm = true;
    bool fuseLmHeadArgmax = true;
    bool deviceArgmaxMerge = true;
    bool materializeFullLogits = false;
};

struct B28PartialArgmax {
    float value = -3.402823466e+38F;
    uint32_t token = 0;
};

class B28DeviceLogits {
public:
    static B28DeviceLogitsPlan make(const B28LogitsShape&, double gpu0Rate,
                                    double gpu1Rate) noexcept;
    static B28PartialArgmax merge(B28PartialArgmax a,
                                  B28PartialArgmax b) noexcept;
    static uint64_t avoidedD2HBytes(const B28LogitsShape&) noexcept;
};

} // namespace Deep2
