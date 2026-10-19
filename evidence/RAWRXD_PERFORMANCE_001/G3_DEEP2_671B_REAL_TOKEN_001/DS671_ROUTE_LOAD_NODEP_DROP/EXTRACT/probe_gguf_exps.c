/* Probe first shard for deepseek2 expert tensor naming + KV. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int rd(FILE *f, void *p, size_t n) {
    return fread(p, 1, n, f) == n ? 0 : 1;
}
static int rd_u32(FILE *f, uint32_t *v) { return rd(f, v, 4); }
static int rd_u64(FILE *f, uint64_t *v) { return rd(f, v, 8); }

static int rd_str(FILE *f, char *buf, size_t cap) {
    uint64_t n = 0;
    if (rd_u64(f, &n)) return 1;
    if (n + 1 > cap) {
        if (fseek(f, (long)n, SEEK_CUR)) return 1;
        buf[0] = 0;
        return 0;
    }
    if (n && rd(f, buf, (size_t)n)) return 1;
    buf[n] = 0;
    return 0;
}

static int skip_val(FILE *f, uint32_t vt) {
    uint32_t at; uint64_t n, i; char tmp[8];
    if (vt <= 1 || vt == 7) return rd(f, tmp, 1);
    if (vt <= 3) return rd(f, tmp, 2);
    if (vt <= 6) return rd(f, tmp, 4);
    if (vt == 8) {
        if (rd_u64(f, &n)) return 1;
        return fseek(f, (long)n, SEEK_CUR) ? 1 : 0;
    }
    if (vt == 9) {
        if (rd_u32(f, &at) || rd_u64(f, &n)) return 1;
        for (i = 0; i < n; ++i) if (skip_val(f, at)) return 1;
        return 0;
    }
    if (vt >= 10 && vt <= 12) return rd(f, tmp, 8);
    return 1;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] :
        "F:/OllamaModels/DeepSeek-R1-Q4_K_M-COMPLETE/"
        "DeepSeek-R1-Q4_K_M-00001-of-00011.gguf";
    FILE *f; char magic[4], key[256], name[256];
    uint32_t ver, vt, nd, tt, found = 0;
    uint64_t n_ten, n_kv, dims[8], off, i, d;
    uint32_t u32; uint64_t u64;

    f = fopen(path, "rb");
    if (!f) { puts("OPEN_FAIL"); return 1; }
    if (rd(f, magic, 4) || rd_u32(f, &ver) || rd_u64(f, &n_ten) ||
        rd_u64(f, &n_kv)) return 2;
    printf("GGUF ver=%u tensors=%llu kv=%llu\n", ver,
           (unsigned long long)n_ten, (unsigned long long)n_kv);

    for (i = 0; i < n_kv; ++i) {
        if (rd_str(f, key, sizeof(key)) || rd_u32(f, &vt)) return 3;
        if (strstr(key, "architecture") || strstr(key, "block_count") ||
            strstr(key, "expert_count") || strstr(key, "expert_used") ||
            strstr(key, "leading_dense") || strstr(key, "embedding_length")) {
            if (vt == 8) {
                if (rd_str(f, name, sizeof(name))) return 4;
                printf("KV %s = %s\n", key, name);
            } else if (vt == 4) {
                if (rd_u32(f, &u32)) return 4;
                printf("KV %s = %u\n", key, u32);
            } else if (vt == 10) {
                if (rd_u64(f, &u64)) return 4;
                printf("KV %s = %llu\n", key, (unsigned long long)u64);
            } else {
                printf("KV %s type=%u\n", key, vt);
                if (skip_val(f, vt)) return 4;
            }
        } else if (skip_val(f, vt)) return 5;
    }

    for (i = 0; i < n_ten && found < 9; ++i) {
        if (rd_str(f, name, sizeof(name)) || rd_u32(f, &nd)) return 6;
        if (nd > 8) return 7;
        for (d = 0; d < nd; ++d) if (rd_u64(f, &dims[d])) return 8;
        if (rd_u32(f, &tt) || rd_u64(f, &off)) return 9;
        if (strstr(name, "ffn_gate_exps") || strstr(name, "ffn_up_exps") ||
            strstr(name, "ffn_down_exps") || strstr(name, "ffn_gate_inp")) {
            printf("T %s nd=%u dims=[", name, nd);
            for (d = 0; d < nd; ++d)
                printf("%s%llu", d ? "," : "", (unsigned long long)dims[d]);
            printf("] type=%u off=%llu\n", tt, (unsigned long long)off);
            found++;
        }
    }
    printf("FOUND=%u\n", found);
    fclose(f);
    return found ? 0 : 10;
}
