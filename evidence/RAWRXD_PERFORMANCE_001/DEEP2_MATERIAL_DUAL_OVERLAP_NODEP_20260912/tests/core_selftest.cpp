#include "../include/d2_material_overlap.h"
#include <stdio.h>
#include <string.h>

static int expect(int cond, const char* s) {
    if (!cond) { printf("FAIL %s\n", s); return 1; }
    printf("PASS %s\n", s); return 0;
}

static D2OverlapReceipt good_receipt(const D2ProductProof* p, const D2OverlapPolicy* pol) {
    D2OverlapReceipt r = {};
    for (int i=0;i<2;i++) {
        r.lane[i].record_rc=0; r.lane[i].submit_rc=0; r.lane[i].wait_rc=0;
        r.lane[i].calibrate_rc=0; r.lane[i].calibration_deviation_ns=1000;
        r.lane[i].packed_bytes=64ull<<20;
    }
    r.lane[0].mapped_start_ns=1000000; r.lane[0].mapped_end_ns=9000000;
    r.lane[1].mapped_start_ns=1500000; r.lane[1].mapped_end_ns=8500000;
    r.compact_reduce_real=1;
    d2_overlap_evaluate(p,pol,&r);
    return r;
}

int main() {
    int bad = 0;
    D2ProductProof p = {};
    p.product_linked=1; p.packed_q2k_live=1;
    D2OverlapPolicy pol = {};
    pol.min_shorter_overlap_permille=700;
    pol.min_critical_overlap_permille=500;
    pol.max_calibration_deviation_ns=50000;
    pol.min_packed_bytes_per_lane=1u<<20;

    D2OverlapReceipt r = good_receipt(&p,&pol);
    bad |= expect(r.material_same_token_overlap==1, "material overlap candidate");
    bad |= expect(r.aggregate_bw_candidate==1, "per-token conjunction candidate");
    bad |= expect(r.aggregate_bw_authority==0, "single token cannot mint authority");

    D2OverlapReceipt tiny = r;
    tiny.lane[0].mapped_start_ns=1000000; tiny.lane[0].mapped_end_ns=8000000;
    tiny.lane[1].mapped_start_ns=7970400; tiny.lane[1].mapped_end_ns=15000000;
    d2_overlap_evaluate(&p,&pol,&tiny);
    bad |= expect(tiny.material_same_token_overlap==0, "tiny overlap rejected");
    bad |= expect(tiny.aggregate_bw_candidate==0, "tiny overlap cannot become candidate");

    D2OverlapReceipt mat = good_receipt(&p,&pol);
    D2ProductProof q = p; q.materialized_weight_bytes=4096;
    d2_overlap_evaluate(&q,&pol,&mat);
    bad |= expect(mat.aggregate_bw_candidate==0, "materialized weights fail closed");

    D2OverlapReceipt mig = good_receipt(&p,&pol);
    q = p; q.weight_migration_bytes=1;
    d2_overlap_evaluate(&q,&pol,&mig);
    bad |= expect(mig.aggregate_bw_candidate==0, "weight migration fail closed");

    D2OverlapReceipt cal = good_receipt(&p,&pol);
    cal.lane[0].calibration_deviation_ns=pol.max_calibration_deviation_ns+1;
    d2_overlap_evaluate(&p,&pol,&cal);
    bad |= expect(cal.material_same_token_overlap==0, "bad calibration fails closed");

    D2OverlapReceipt window[16];
    for (int i=0;i<16;i++) window[i]=good_receipt(&p,&pol);
    D2OverlapWindowPolicy wp = {16,1000};
    D2OverlapWindowReceipt wr = {};
    d2_overlap_window_evaluate(window,16,&wp,&wr);
    bad |= expect(wr.aggregate_bw_authority==1, "16/16 repeated tokens mint authority");
    window[7]=tiny;
    d2_overlap_window_evaluate(window,16,&wp,&wr);
    bad |= expect(wr.aggregate_bw_authority==0, "15/16 rejected by strict window");

    printf("CORE_SELFTEST=%s\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
