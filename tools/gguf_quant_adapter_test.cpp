// gguf_quant_adapter_test.cpp -- verify native GGUF Q4_0 / Q4_K dequant against
// the GGUF specification with hand-computed reference values.
// Build: g++ -std=c++17 -O2 -I include -I src tools/gguf_quant_adapter_test.cpp -o gqa
#include "deep2/GgufQuantAdapter.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace rawrxd::gguf;

int main() {
    int fails = 0;

    // ---- Q4_0: 1 block (32 values), 18 bytes ----
    {
        std::vector<uint8_t> blk(18, 0);
        // d = 0.5 (fp16 0x3800)
        blk[0] = 0x00; blk[1] = 0x38;
        // qs[0] = 0x10 -> q0=0, q1=1
        blk[2] = 0x10;
        // qs[1] = 0x32 -> q2=2, q3=3
        blk[3] = 0x32;
        // qs[2] = 0x54 -> q4=4, q5=5
        blk[4] = 0x54;
        // qs[3] = 0x76 -> q6=6, q7=7
        blk[5] = 0x76;
        // rest zeros -> q=0
        std::vector<float> out;
        DequantizeQ4_0(blk.data(), 1, out);
        // Expected: d*(q-8) = 0.5*(q-8)
        // q0=0 -> -4.0, q1=1 -> -3.5, q2=2 -> -3.0, q3=3 -> -2.5, ...
        float exp0 = 0.5f * (0 - 8);
        float exp1 = 0.5f * (1 - 8);
        float exp2 = 0.5f * (2 - 8);
        float exp7 = 0.5f * (7 - 8);
        bool ok = (out.size() == 32) &&
                  std::fabs(out[0] - exp0) < 1e-6 &&
                  std::fabs(out[1] - exp1) < 1e-6 &&
                  std::fabs(out[2] - exp2) < 1e-6 &&
                  std::fabs(out[7] - exp7) < 1e-6;
        std::printf("Q4_0: out[0]=%g (exp %g) out[1]=%g (exp %g) %s\n",
                    out[0], exp0, out[1], exp1, ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // ---- Q4_K: 1 superblock (256 values), 144 bytes ----
    {
        std::vector<uint8_t> blk(144, 0);
        // d = 1.0 (fp16 0x3C00), dmin = 0.0
        blk[0] = 0x00; blk[1] = 0x3C; // d = 1.0
        blk[2] = 0x00; blk[3] = 0x00; // dmin = 0.0
        // scales[12]: set sub-block 0 scale = 1 (6-bit value 1 at bit 0), min = 0
        blk[4] = 0x01; // scales[0] = 0x01 -> subScale[0] = 1
        // qs[128]: all 4-bit values = 0 except sub-block 0 first byte = 0x10 (q0=0,q1=1)
        blk[16] = 0x10; // qs[0]
        std::vector<float> out;
        DequantizeQ4_K(blk.data(), 1, out);
        // sub-block 0: scale = d*scale[0] = 1.0*1 = 1.0, min = dmin*min[0] = 0
        // q0=0 -> 0.0, q1=1 -> 1.0
        bool ok = (out.size() == 256) &&
                  std::fabs(out[0] - 0.0f) < 1e-6 &&
                  std::fabs(out[1] - 1.0f) < 1e-6;
        std::printf("Q4_K: out[0]=%g (exp 0) out[1]=%g (exp 1) %s\n",
                    out[0], out[1], ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    std::printf("RESULT=%s fails=%d\n", fails == 0 ? "PASS" : "FAIL", fails);
    return fails == 0 ? 0 : 1;
}