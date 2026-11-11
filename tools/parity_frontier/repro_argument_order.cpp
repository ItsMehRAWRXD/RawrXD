#include <cassert>
#include <cstdio>
#include <vector>
struct Arena {
    std::vector<float> out;
    float* GetOrCreate() { out.resize(12); return out.data(); }
    size_t Size() const { return out.size(); }
};
static bool TopK(float* output, size_t outputN) {
    (void)output;
    return outputN == 12;
}
int main() {
    Arena old;
    const bool oldDispatch = TopK(old.GetOrCreate(), old.Size());
    Arena repaired;
    float* output = repaired.GetOrCreate();
    const size_t outputN = repaired.Size();
    const bool repairedDispatch = TopK(output, outputN);
    std::printf("UNSEQUENCED_ARGUMENT_CALL_RESULT=%d OUTPUT_SIZE_AFTER=%zu\n", oldDispatch, old.Size());
    std::printf("SEQUENCED_ARGUMENT_CALL_RESULT=%d OUTPUT_SIZE_AFTER=%zu\n", repairedDispatch, repaired.Size());
    assert(repairedDispatch);
}
