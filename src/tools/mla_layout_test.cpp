// Regression test for the fused attn_kv_b expansion layout.
//
// Multi-head Latent Attention expands the compressed latent into per-head
// keys and values with one fused up-projection matrix. llama.cpp's
// deepseek2.cpp expands it one row block per head: head h owns
// qkNope + vHead consecutive rows, the first qkNope of which are that
// head's key and the rest its value.
//
// Treating the rows as if they were grouped by projection instead - the
// layout the MLA absorption optimization uses, which needs the *split*
// attn_k_b and attn_v_b tensors - gives every head the wrong weights, and
// the attention then produces NaN hidden states. That mistake was made
// twice in this tree, once silently, so the layout is pinned here.
//
//   mla_layout_test [--model <model.gguf>] [--print-golden]
//
// With no model the test runs the synthetic layout check, which needs
// nothing but the contract. With a model it also checks the expansion
// against a golden vector captured from a verified run.

#include "core/Deep2Types.hpp"
#include "core/MlaLayout.hpp"
#include "core/QuantBlockTraits.hpp"
#include "TensorROM.hpp"
#include "quant_kernels.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace Deep2Rom;

namespace {

int g_failures = 0;

void expect(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "[PASS] " << what << "\n";
    } else {
        std::cout << "[FAIL] " << what << "\n";
        ++g_failures;
    }
}

// The geometry of DeepSeek-V2-Lite, which is the model the fused layout
// exists for.
constexpr uint32_t kHeads   = 16;
constexpr uint32_t kQkNope  = 128;
constexpr uint32_t kVHead   = 128;
constexpr uint32_t kKvLora  = 512;

MlaKvBLayout layout() {
    MlaKvBLayout l;
    l.numHeads = kHeads;
    l.qkNope   = kQkNope;
    l.vHead    = kVHead;
    l.kvLora   = kKvLora;
    return l;
}

// Expand the fused matrix the way the MLA attention does. This calls the
// same shared routine the engine uses, so the test guards the real
// expansion rather than a copy of it.
void expandFused(const std::vector<float>& fused, const MlaKvBLayout& l,
                 std::vector<float>& keys, std::vector<float>& values) {
    expandFusedAttnKvB(fused.data(), l, keys, values);
}

// The layout a reader would use if it wrongly grouped the rows by
// projection: every head's key first, then every head's value.
void expandGrouped(const std::vector<float>& fused, const MlaKvBLayout& l,
                   std::vector<float>& keys, std::vector<float>& values) {
    keys.assign((size_t)l.numHeads * l.qkNope, 0.0f);
    values.assign((size_t)l.numHeads * l.vHead, 0.0f);
    for (uint32_t h = 0; h < l.numHeads; ++h) {
        for (uint32_t d = 0; d < l.qkNope; ++d) {
            keys[(size_t)h * l.qkNope + d] = fused[(uint64_t)h * l.qkNope + d];
        }
    }
    const uint64_t vBase = (uint64_t)l.numHeads * l.qkNope;
    for (uint32_t h = 0; h < l.numHeads; ++h) {
        for (uint32_t d = 0; d < l.vHead; ++d) {
            values[(size_t)h * l.vHead + d] = fused[vBase + (uint64_t)h * l.vHead + d];
        }
    }
}

// The synthetic check. Every element of the fused matrix encodes its own
// coordinates, so the expansion can be checked exactly.
void runSyntheticCheck() {
    const MlaKvBLayout l = layout();
    expect(l.rowsPerHead() == kQkNope + kVHead, "rows per head is qkNope + vHead");
    expect(l.totalRows() == (uint32_t)(kHeads * (kQkNope + kVHead)),
           "the fused matrix has numHeads * (qkNope + vHead) rows");
    expect(l.keyRow(0) == 0 && l.valueRow(0) == kQkNope,
           "head 0 owns the key rows first and the value rows second");
    expect(l.keyRow(1) == kQkNope + kVHead,
           "head 1 starts after head 0's whole block, not after the key rows");
    expect(l.valueRow(3) == 3 * (kQkNope + kVHead) + kQkNope,
           "head 3's value rows follow its key rows");

    // A matrix where element (r, c) is r * 1000 + c.
    std::vector<float> fused((size_t)l.totalRows() * l.kvLora);
    for (uint32_t r = 0; r < l.totalRows(); ++r) {
        for (uint32_t c = 0; c < l.kvLora; ++c) {
            fused[(size_t)r * l.kvLora + c] = (float)(r * 1000 + c);
        }
    }

    std::vector<float> keys, values;
    expandFused(fused, l, keys, values);

    // The expansion must place exactly the rows the contract names.
    bool ok = true;
    for (uint32_t h = 0; h < l.numHeads && ok; ++h) {
        for (uint32_t d = 0; d < l.qkNope; ++d) {
            const float want = (float)(l.keyRow(h) * 1000 + d);
            if (keys[(size_t)h * l.qkNope + d] != want) { ok = false; break; }
        }
        for (uint32_t d = 0; d < l.vHead; ++d) {
            const float want = (float)(l.valueRow(h) * 1000 + d);
            if (values[(size_t)h * l.vHead + d] != want) { ok = false; break; }
        }
    }
    expect(ok, "the expansion places each head's key and value rows exactly where the contract says");

    // And the grouped interpretation must give a different answer, so that
    // swapping the layout is detectable rather than silent.
    std::vector<float> gKeys, gValues;
    expandGrouped(fused, l, gKeys, gValues);
    bool differs = false;
    for (size_t i = 0; i < keys.size() && !differs; ++i) {
        if (keys[i] != gKeys[i]) differs = true;
    }
    expect(differs, "the grouped-by-projection layout gives different keys, so a swap is detectable");
}

// The golden vector, captured from a verified run against
// DeepSeek-V2-Lite-Chat.Q4_K_M.gguf, layer 1.
//
// These are the first few expanded key and value floats for head 0 and
// head 1. They pin the layout of the real weight matrix.
const float kGoldenHead0Key[4]   = { 0.00307274f, 0.0262909f, -0.0433636f, -0.0317545f };
const float kGoldenHead0Value[4] = { -0.00600243f, 0.0259495f, -0.00600243f, -0.0299664f };
const float kGoldenHead1Key[4]   = { -0.00308347f, -0.159771f, -0.00308347f, -0.0254674f };

void runGoldenCheck(const std::string& modelPath) {
    deep2::TensorROM rom;
    if (!rom.addShard(modelPath) || !rom.finalizeIndex()) {
        std::cout << "[SKIP] could not open " << modelPath << "\n";
        return;
    }
    const deep2::TensorEntry* e = rom.findTensor("blk.1.attn_kv_b.weight");
    if (!e) {
        std::cout << "[SKIP] " << modelPath << " has no blk.1.attn_kv_b.weight\n";
        return;
    }

    const std::uint64_t bytes = e->byteSize();
    std::vector<std::uint8_t> raw(bytes);
    if (!rom.readTensor(*e, raw.data())) {
        std::cout << "[FAIL] could not read attn_kv_b\n";
        ++g_failures;
        return;
    }

    deep2::TensorView view{ e->type, raw.data(), bytes, e->dims, true };
    deep2::DequantizedTensor dq;
    if (!dequantizeTensor(view, dq)) {
        std::cout << "[FAIL] could not dequantize attn_kv_b\n";
        ++g_failures;
        return;
    }

    const MlaKvBLayout l = layout();
    if (dq.rows != l.totalRows() || dq.cols != l.kvLora) {
        std::cout << "[FAIL] attn_kv_b is " << dq.rows << "x" << dq.cols
                  << ", expected " << l.totalRows() << "x" << l.kvLora << "\n";
        ++g_failures;
        return;
    }

    std::vector<float> keys, values;
    expandFused(dq.data, l, keys, values);

    const float* goldenKeys[2]   = { kGoldenHead0Key, kGoldenHead1Key };
    const float* goldenValues[1] = { kGoldenHead0Value };
    auto close = [](float a, float b) {
        const float d = std::fabs(a - b);
        return d <= 1e-4f * std::fmax(1.0f, std::fmax(std::fabs(a), std::fabs(b)));
    };

    bool ok = true;
    for (int h = 0; h < 2 && ok; ++h) {
        for (int i = 0; i < 4; ++i) {
            if (!close(keys[(size_t)h * l.qkNope + i], goldenKeys[h][i])) ok = false;
        }
    }
    for (int i = 0; i < 4 && ok; ++i) {
        if (!close(values[i], goldenValues[0][i])) ok = false;
    }
    expect(ok, "the real attn_kv_b expansion matches the golden vector");

    // Print the current values so the golden vector can be refreshed.
    std::printf("[GOLDEN]\n");
    std::printf("kGoldenHead0Key  = { ");
    for (int i = 0; i < 4; ++i) std::printf("%s%gf", i ? ", " : "", keys[i]);
    std::printf(" };\n");
    std::printf("kGoldenHead0Value= { ");
    for (int i = 0; i < 4; ++i) std::printf("%s%gf", i ? ", " : "", values[i]);
    std::printf(" };\n");
    std::printf("kGoldenHead1Key  = { ");
    for (int i = 0; i < 4; ++i) std::printf("%s%gf", i ? ", " : "", keys[(size_t)l.qkNope + i]);
    std::printf(" };\n");
}

}  // namespace

int main(int argc, char** argv) {
    std::string modelPath;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            modelPath = argv[++i];
        }
    }

    runSyntheticCheck();

    if (!modelPath.empty()) {
        runGoldenCheck(modelPath);
    } else {
        std::cout << "[SKIP] no model given, the golden vector check did not run\n";
    }

    if (g_failures) {
        std::cout << "[RESULT] " << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "[RESULT] all checks passed\n";
    return 0;
}
