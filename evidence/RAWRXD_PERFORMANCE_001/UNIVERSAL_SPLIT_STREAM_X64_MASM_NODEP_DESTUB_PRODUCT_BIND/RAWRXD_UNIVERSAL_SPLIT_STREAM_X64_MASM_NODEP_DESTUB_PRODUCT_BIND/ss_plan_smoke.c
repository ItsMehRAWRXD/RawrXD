/* ss_plan_smoke.c — argv model path → MODEL_PLAN_REAL; fixture = NOT_RUN skip */
#include "ss_model_plan.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    static SsModelPlan p;
    const char *path = argc > 1 ? argv[1] : 0;
    if (!path) {
        printf("MODEL_PLAN_SMOKE=NOT_RUN REASON=NO_PATH PROMOTE=0\n");
        return 0;
    }
    memset(&p, 0, sizeof p);
    if (ss_model_plan_build_split(path, &p) == 0 && p.planReal) {
        ss_model_plan_print(&p);
        ss_model_plan_print_inventory(&p);
        printf("MODEL_PLAN_SMOKE=PASS FULL_MODEL_FORWARD=0 PROMOTE=0\n");
        return 0;
    }
    if (!p.metaReal) {
        printf("MODEL_PLAN_SMOKE=NOT_RUN REASON=NO_ARCH_META FULL_MODEL_FORWARD=0\n");
        return 0;
    }
    ss_model_plan_print(&p);
    printf("MODEL_PLAN_SMOKE=FAIL BLOCKS_PRESENT=%u EXPECTED=%u\n",
           p.blocksPresent, p.blockCount);
    return 1;
}
