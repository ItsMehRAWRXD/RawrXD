#include "../src/deep2/RawrNormalGgufFinal.hpp"
#include "../src/deep2/Deep2DetokenUtf8.hpp"
#include <cstdio>
#include <string>
#include <vector>
int main() {
    // Mechanical quality witness on a known-good paragraph (unit path).
    // Full model coherence remains RAWRXD_NORMAL_GGUF_FINAL_001.
    std::string good =
        "The quick brown fox jumps over the lazy dog. "
        "This paragraph is coherent English text.";
    std::vector<int> ids = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto w = Deep2::normal_gguf::ScoreQuality(good, ids);
    if (!w.utf8Valid || w.debugInOutput || !Deep2::IsValidUtf8(good)) {
        puts("RAWRXD_RUN_QUALITY_001=FAIL");
        return 1;
    }
    if (w.alphaCount < 20 || w.spaceCount < 5) {
        puts("RAWRXD_RUN_QUALITY_001=FAIL");
        return 1;
    }
    puts("RAWRXD_RUN_QUALITY_001=PASS");
    return 0;
}
