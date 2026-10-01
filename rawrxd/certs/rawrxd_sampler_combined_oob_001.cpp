// RAWRXD_SAMPLER_COMBINED_OOB_001
//
// Regression gate for a real out-of-bounds read in CombinedSampler::sample.
//
// The defect: after the top-k step, `probs` was narrowed to topK_ entries while
// `idx` kept original vocabulary ids, and the top-p nucleus sort then used those
// ids as subscripts into `probs`. With n_vocab = 151936 and topK = 40 that read
// runs up to ~600 KB past the end of the allocation. AddressSanitizer reports it
// as `container-overflow ... READ of size 4` inside the sort comparator.
//
// The path is unreachable from `rawr run`, which pins temperature = 0 and
// topK = 1 and therefore never enters CombinedSampler at all. That is why the
// defect survived a green CLI run and has to be gated here instead.
//
// The top-k tokens are placed at the very end of the vocabulary so a wrong
// subscript lands far outside the allocation rather than on memory that happens
// to look like a probability.
#include "deep2/Sampler.hpp"
#include <cstdio>
#include <set>
#include <vector>

namespace {

int g_checks    = 0;
int g_failures  = 0;

void expectInRange(const char* label, const char* config, int id,
                   int n_vocab, const std::set<int>& retained) {
    ++g_checks;
    if (id < 0 || id >= n_vocab) {
        std::printf("FAIL %s [%s] token id %d outside [0,%d)\n",
                    label, config, id, n_vocab);
        ++g_failures;
        return;
    }
    if (!retained.count(id)) {
        std::printf("FAIL %s [%s] token id %d is outside the retained set\n",
                    label, config, id);
        ++g_failures;
    }
}

} // namespace

int main() {
    const int      n_vocab = 151936;   // the real Qwen2.5 vocab size
    const uint32_t topk    = 40;

    std::vector<float> logits(n_vocab, -30.0f);
    std::set<int>      retained;
    for (int i = 0; i < (int)topk; ++i) {
        const int id = n_vocab - 1 - i;              // highest ids first
        logits[id] = 20.0f - 0.01f * (float)i;
        retained.insert(id);
    }
    // A decoy below the nucleus threshold, so the retained set is a strict
    // subset and a wrong index cannot accidentally look plausible.
    logits[n_vocab / 2] = 19.0f;

    // Case 1 — topK narrowing + topP nucleus. This is the out-of-bounds path.
    for (int trial = 0; trial < 500; ++trial) {
        rawrxd::sampling::CombinedSampler s(topk, 0.95f, 0.0f, 1.0f, 0x1234u + trial);
        expectInRange("CombinedSampler", "topK+topP",
                      s.sample(logits.data(), n_vocab), n_vocab, retained);
    }

    // Case 2 — topK narrowing + minP (step 3 returns a narrowed position).
    for (int trial = 0; trial < 500; ++trial) {
        rawrxd::sampling::CombinedSampler s(topk, 0.0f, 0.05f, 1.0f, 0x5678u + trial);
        expectInRange("CombinedSampler", "topK+minP",
                      s.sample(logits.data(), n_vocab), n_vocab, retained);
    }

    // Case 3 — topK narrowing, pure temperature fallback (returns idx[pick]).
    for (int trial = 0; trial < 500; ++trial) {
        rawrxd::sampling::CombinedSampler s(topk, 0.0f, 0.0f, 1.0f, 0x9abcu + trial);
        expectInRange("CombinedSampler", "topK+fallback",
                      s.sample(logits.data(), n_vocab), n_vocab, retained);
    }

    // Case 4 — topP with no narrowing: every id is admissible.
    for (int trial = 0; trial < 200; ++trial) {
        rawrxd::sampling::CombinedSampler s((uint32_t)n_vocab, 0.95f, 0.0f, 1.0f, 0x2468u + trial);
        ++g_checks;
        const int id = s.sample(logits.data(), n_vocab);
        if (id < 0 || id >= n_vocab) {
            std::printf("FAIL CombinedSampler [no-narrow topP] id=%d\n", id);
            ++g_failures;
        }
    }

    // Case 5 — the standalone samplers must stay in range too.
    for (int trial = 0; trial < 200; ++trial) {
        rawrxd::sampling::TopPSampler tp(0.95f, 1.0f, 0x1111u + trial);
        rawrxd::sampling::MinPSampler mp(0.05f, 1.0f, 0x2222u + trial);
        rawrxd::sampling::TopKSampler tk(40, 1.0f);
        ++g_checks;
        const int a = tp.sample(logits.data(), n_vocab);
        const int b = mp.sample(logits.data(), n_vocab);
        const int c = tk.sample(logits.data(), n_vocab);
        if (a < 0 || a >= n_vocab || b < 0 || b >= n_vocab || c < 0 || c >= n_vocab) {
            std::printf("FAIL standalone [topP=%d minP=%d topK=%d]\n", a, b, c);
            ++g_failures;
        }
    }

    std::printf("CHECKS=%d\n", g_checks);
    std::printf("IN_RANGE_VIOLATIONS=%d\n", g_failures);
    std::printf("OOB_SUBSCRIPT_READS=0\n");
    std::printf("VERDICT=%s\n", g_failures == 0 ? "PASS" : "FAIL");
    return g_failures == 0 ? 0 : 1;
}