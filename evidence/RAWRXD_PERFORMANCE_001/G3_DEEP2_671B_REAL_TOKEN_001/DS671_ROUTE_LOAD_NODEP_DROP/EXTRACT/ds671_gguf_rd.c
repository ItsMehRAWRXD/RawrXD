#include "ds671_gguf_rd.h"
#include "ds671_tensor_adapter.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int ds671_gguf_rd(FILE *f, void *p, size_t n) {
    return fread(p, 1, n, f) == n ? 0 : 1;
}
int ds671_gguf_ru32(FILE *f, uint32_t *v) { return ds671_gguf_rd(f, v, 4); }
int ds671_gguf_ru64(FILE *f, uint64_t *v) { return ds671_gguf_rd(f, v, 8); }

int ds671_gguf_rstr(FILE *f, char *b, size_t cap) {
    uint64_t n = 0;
    if (ds671_gguf_ru64(f, &n)) return 1;
    if (n + 1 > cap) {
        if (fseek(f, (long)n, SEEK_CUR)) return 1;
        b[0] = 0; return 0;
    }
    if (n && ds671_gguf_rd(f, b, (size_t)n)) return 1;
    b[n] = 0; return 0;
}

int ds671_gguf_skipv(FILE *f, uint32_t vt) {
    uint32_t at; uint64_t n, i; char t[8];
    if (vt <= 1 || vt == 7) return ds671_gguf_rd(f, t, 1);
    if (vt <= 3) return ds671_gguf_rd(f, t, 2);
    if (vt <= 6) return ds671_gguf_rd(f, t, 4);
    if (vt == 8) {
        if (ds671_gguf_ru64(f, &n)) return 1;
        return fseek(f, (long)n, SEEK_CUR) ? 1 : 0;
    }
    if (vt == 9) {
        if (ds671_gguf_ru32(f, &at) || ds671_gguf_ru64(f, &n)) return 1;
        for (i = 0; i < n; ++i) if (ds671_gguf_skipv(f, at)) return 1;
        return 0;
    }
    if (vt >= 10 && vt <= 12) return ds671_gguf_rd(f, t, 8);
    return 1;
}

int ds671_gguf_parse_exps(const char *name, uint32_t *blk, uint32_t *proj) {
    unsigned b = 0; const char *p;
    if (sscanf(name, "blk.%u.ffn_", &b) != 1) return -1;
    p = strstr(name, "ffn_");
    if (!p) return -1;
    p += 4;
    if (!strncmp(p, "gate_exps.weight", 16)) *proj = DS671_PROJ_GATE;
    else if (!strncmp(p, "up_exps.weight", 14)) *proj = DS671_PROJ_UP;
    else if (!strncmp(p, "down_exps.weight", 16)) *proj = DS671_PROJ_DOWN;
    else return -1;
    *blk = b;
    return 0;
}
