// v02_slice_test.cpp — CPU functional test for the storage-independent slicing.
#include "reap/ReapTensorSlice.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    SliceTensorDesc t; t.name = "blk.0.ffn.experts"; t.dims = {4096, 8}; t.bytes = 8 * 4096 * 2; // Q4-ish, 8 experts
    ExpertSelection sel{{0, {1, 3, 5}}};
    auto r = SliceExperts(t, 0, sel);
    ck(r.ok, "slice_ok");
    ck(r.stride == 4096 * 2, "stride");
    ck(r.ranges.size() == 3, "range_count");
    ck(r.ranges[0].first == 1 * r.stride, "offset_expert1");
    ck(r.ranges[2].first == 5 * r.stride, "offset_expert5");
    // Reject out-of-range expert.
    ExpertSelection bad{{0, {9}}};
    ck(!SliceExperts(t, 0, bad).ok, "reject_oob_expert");
    // Reject missing layer.
    ExpertSelection miss{{1, {0}}};
    ck(!SliceExperts(t, 0, miss).ok, "reject_missing_layer");
    std::printf("FAILS=%d\nV02_SLICE=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}