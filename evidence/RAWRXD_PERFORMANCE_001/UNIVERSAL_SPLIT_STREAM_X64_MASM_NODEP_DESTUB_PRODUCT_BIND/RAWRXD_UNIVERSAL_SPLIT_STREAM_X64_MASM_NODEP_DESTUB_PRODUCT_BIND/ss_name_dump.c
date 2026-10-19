/* ss_name_dump.c — list blk.N tensor names across shards */
#include "ss_model_plan_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int dump_shard(const char *path, int want)
{
    FILE *f; char arch[64], needle[32]; uint32_t align = 32, nd, ty;
    uint64_t nt, i, j, elems, off, dims[4]; SsModelPlan tmp; SsPlanEnt *e = 0;
    memset(&tmp, 0, sizeof tmp);
    f = fopen(path, "rb"); if (!f) return 1;
    arch[0] = 0;
    if (ss_mp_read_meta(f, &tmp, arch, &align, &nt, 0)) { fclose(f); return 1; }
    e = (SsPlanEnt *)calloc((size_t)nt, sizeof(SsPlanEnt));
    if (!e) { fclose(f); return 1; }
    for (i = 0; i < nt; ++i) {
        elems = 1;
        if (ss_mp_rstr(f, e[i].name, sizeof e[i].name) || ss_mp_rd(f, &nd, 4) || nd > 4)
            { free(e); fclose(f); return 1; }
        for (j = 0; j < nd; ++j) {
            if (ss_mp_rd(f, &dims[j], 8)) { free(e); fclose(f); return 1; }
            elems *= dims[j]; e[i].dims[j] = dims[j];
        }
        if (ss_mp_rd(f, &ty, 4) || ss_mp_rd(f, &off, 8)) { free(e); fclose(f); return 1; }
        e[i].nd = nd; e[i].ty = ty; e[i].rel = off; e[i].elems = elems;
    }
    sprintf(needle, "blk.%d.", want);
    for (i = 0; i < nt; ++i)
        if (strstr(e[i].name, needle)) printf("%s\n", e[i].name);
    free(e); fclose(f); return 0;
}
int main(void)
{
    char path[512]; int s;
    for (s = 0; s < 11; ++s) {
        sprintf(path,
            "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-%05d-of-00011.gguf",
            s + 1);
        printf("--- shard %d ---\n", s);
        dump_shard(path, 13);
    }
    return 0;
}
