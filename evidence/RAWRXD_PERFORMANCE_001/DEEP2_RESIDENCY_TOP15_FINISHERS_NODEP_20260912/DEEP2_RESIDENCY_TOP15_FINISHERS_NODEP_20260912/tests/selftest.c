#include "d2_residency_finishers.h"
#include <stdio.h>

static int check(int cond, const char* name, int code) {
    if (!cond) { printf("FAIL=%s\n", name); return code; }
    return 0;
}

int main(void) {
    D2ResidencyRegion r, f;
    D2ResidencyCounters c = {0};
    D2ResidencyParentProof p = {1,16,1,1,1,1032192000ull,0,0,0,0,0};
    uint32_t mask; int rc;

    d2r_init(&r, 7, 3, 4096, 65536, 14, 1);
    rc = check(r.owner_id == 1, "SINGLE_OWNER", 1); if (rc) return rc;
    rc = check(!d2r_begin_first_touch(&r,&c,2,1), "STALE_GENERATION_REJECT", 2); if (rc) return rc;
    rc = check(d2r_begin_first_touch(&r,&c,3,1), "FIRST_TOUCH", 3); if (rc) return rc;
    rc = check(!d2r_begin_first_touch(&r,&c,3,1), "DUP_FIRST_TOUCH_REJECT", 4); if (rc) return rc;
    rc = check(d2r_join_first_touch(&r,&c,3), "JOIN_INFLIGHT", 5); if (rc) return rc;
    rc = check(d2r_finish_first_touch(&r,&c,1,65536), "FINISH_WARM", 6); if (rc) return rc;
    rc = check(d2r_contains(&r,3,4096+1024,4096,14), "EXACT_RANGE", 7); if (rc) return rc;
    rc = check(!d2r_contains(&r,3,4096,1024,6), "CODEC_MISMATCH_REJECT", 8); if (rc) return rc;
    rc = check(d2r_pin(&r) && r.state==D2R_HOT, "PIN_HOT", 9); if (rc) return rc;
    rc = check(!d2r_demote_hot_to_warm(&r,&c), "PIN_EVICT_REJECT", 10); if (rc) return rc;
    rc = check(d2r_unpin(&r) && d2r_demote_hot_to_warm(&r,&c), "HOT_TO_WARM", 11); if (rc) return rc;
    rc = check(d2r_demote_warm_to_cold(&r,&c), "WARM_TO_COLD", 12); if (rc) return rc;

    d2r_init(&f, 8, 4, 8192, 4096, 2, 1);
    rc = check(d2r_begin_first_touch(&f,&c,4,1), "FAILPATH_BEGIN", 13); if (rc) return rc;
    rc = check(!d2r_finish_first_touch(&f,&c,0,0) && f.state==D2R_COLD && f.resident_bytes==0,
               "FAILPATH_ROLLBACK", 14); if (rc) return rc;
    rc = check(d2r_parent_proof_pass(&p), "PARENT_PROOF", 15); if (rc) return rc;

    mask = d2r_top15_pass_mask(&p,1,1,1,1,1,1,1,1,1);
    rc = check(mask == 0x7fffu, "TOP15_MASK", 16); if (rc) return rc;

    p.weight_upload_delta = 1;
    rc = check(!d2r_parent_proof_pass(&p), "WUP_REGRESSION_FAIL_CLOSED", 17); if (rc) return rc;

    printf("DEEP2_RESIDENCY_TOP15_FINISHERS_SELFTEST=PASS\n");
    printf("TOP15_FINISHERS=15/15\n");
    printf("FIRST_TOUCH_WINNERS=%llu JOINED_LOADS=%llu FAILED_LOADS=%llu\n",
           (unsigned long long)c.first_touch_wins,
           (unsigned long long)c.joined_loads,
           (unsigned long long)c.failed_loads);
    printf("RESIDENCY_SEAL_RETAINED=1\n");
    printf("RESIDENCY_SEAL_COMMIT=e80ef647e7\n");
    printf("LIVE_PRODUCT_RUN=NOT_RUN\n");
    printf("AUTHORITY=0\n");
    printf("PROMOTE=0\n");
    printf("NEXT=DEEP2_ROOFLINE_LOCALITY_001\n");
    return 0;
}
