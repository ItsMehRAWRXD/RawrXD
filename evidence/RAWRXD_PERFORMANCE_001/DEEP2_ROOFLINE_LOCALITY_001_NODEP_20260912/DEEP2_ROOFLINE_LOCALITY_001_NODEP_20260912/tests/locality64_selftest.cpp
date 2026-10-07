#include "Deep2Locality64.hpp"
#include <cassert>
#include <cstdint>
#include <cstdio>

using namespace Deep2;

static void fill_pass(Locality64Collector& c) {
    c.reset();
    c.setArmed(true);
    c.beginWindow(1000000);
    for (uint64_t i = 0; i < 64; ++i) {
        const uint64_t b = 1000000 + i * 10000000;
        c.beginToken(i, b);
        c.noteDemand(LocalityKind::Weight, 1000, true);
        c.noteDemand(LocalityKind::KV, 100, i < 48); // 16*100 remote total
        c.noteDemand(LocalityKind::Activation, 20, false);
        c.noteHostToDevice(20, true);
        c.noteGpuForwardSpan(0, i, b + 100, b + 5000000);
        c.noteGpuForwardSpan(1, i, b + 200, b + 4500000);
        c.endToken(i, b + 8000000);
    }
    c.endWindow(1000000 + 64 * 10000000);
}

int main() {
    Locality64Collector c;
    fill_pass(c);

    Locality64ParentSeal p{};
    p.bind16_sealed = p.persistent_decode_sealed = p.residency_sealed = true;
    p.weight_upload_delta = p.device_create_delta = p.model_load_delta = 0;
    p.reload_bytes_delta = p.pin_evict_delta = 0;

    Locality64Policy unset{};
    auto hold = c.evaluate(p, unset);
    assert(!hold.conjunction);                 // no invented threshold
    assert(!hold.threshold_configured);

    Locality64Policy ok{};
    ok.max_nonlocal_bytes_per_token = 1000;
    auto pass = c.evaluate(p, ok);
    assert(pass.conjunction);
    assert(pass.s.measured_tokens == 64);
    assert(pass.s.same_token_overlap_count == 64);
    assert(pass.s.gpu0_forward_count == 64 && pass.s.gpu1_forward_count == 64);

    Locality64ParentSeal regress = p;
    regress.weight_upload_delta = 1;
    auto fail = c.evaluate(regress, ok);
    assert(!fail.conjunction);                 // RESIDENCY regression stays fatal

    Locality64Policy tight = ok;
    tight.max_nonlocal_bytes_per_token = 1;
    auto locality_fail = c.evaluate(p, tight);
    assert(!locality_fail.conjunction);

    std::puts("DEEP2_ROOFLINE_LOCALITY_SELFTEST=PASS");
    std::puts("TOP15_FINISHERS=15/15");
    std::puts("LIVE_PRODUCT_RUN=NOT_RUN");
    std::puts("PROMOTE=0");
    return 0;
}
