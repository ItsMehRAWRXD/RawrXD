/* nugv_kv_dump.c -- GGUF metadata key census (structural region only)
 *
 * Companion to nugv_param_probe.c. The probe proves the tensor directory is
 * exact; this enumerates every metadata key so the Model Genie can be driven
 * by what the file actually states rather than by an assumed key set.
 *
 * Reads: header + KV block. Never touches tensor payload.
 *
 * BUILD
 *   cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS nugv_kv_dump.c /Fe:nugv_kv_dump.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_MSC_VER)
#  define NUGV_TELL() _ftelli64(f)
#  define NUGV_SEEK(o, w) _fseeki64(f, (long long)(o), w)
#else
#  define NUGV_TELL() (long long)ftell(f)
#  define NUGV_SEEK(o, w) fseeko(f, (off_t)(o), w)
#endif

static FILE *f;
static int   fail;
static uint64_t bytes_read = 0, max_end = 0;

static void rd(void *p, size_t n) {
    if (fail) return;
    long long before = NUGV_TELL();
    if (before < 0) { fail = 1; return; }
    if (fread(p, 1, n, f) != n) { fail = 1; return; }
    bytes_read += n;
    if ((uint64_t)before + n > max_end) max_end = (uint64_t)before + n;
}
static uint32_t ru32(void) { uint32_t v = 0; rd(&v, 4); return v; }
static uint64_t ru64(void) { uint64_t v = 0; rd(&v, 8); return v; }
static void skipn(uint64_t n) { if (NUGV_SEEK((long long)n, SEEK_CUR) != 0) fail = 1; }

static void rstr(char *b, size_t cap) {
    uint64_t n = ru64();
    if (fail) return;
    if (n + 1 > cap) { skipn(n); b[0] = 0; return; }
    if (n) rd(b, (size_t)n);
    b[n] = 0;
}

static const char *vt_name(uint32_t vt) {
    switch (vt) {
    case 0:  return "u8";
    case 1:  return "i8";
    case 2:  return "u16";
    case 3:  return "i16";
    case 4:  return "u32";
    case 5:  return "i32";
    case 6:  return "f32";
    case 7:  return "bool";
    case 8:  return "string";
    case 9:  return "array";
    case 10: return "u64";
    case 11: return "i64";
    case 12: return "f64";
    default: return "?";
    }
}

static uint64_t g_arr_scalar_total = 0;
static uint32_t g_arr_scalar_max  = 0;
static char     g_biggest_key[256] = { 0 };

static void scan_value(const char *key, uint32_t vt, int depth);

static void scan_array(const char *key, uint32_t et, uint64_t n, int depth) {
    uint64_t i;
    if (et == 8) {                     /* string array */
        for (i = 0; i < n && !fail; ++i) {
            char tmp[8];
            rstr(tmp, sizeof tmp);
        }
        return;
    }
    if (et == 9) {                     /* nested arrays */
        for (i = 0; i < n && !fail; ++i) {
            uint32_t nat = ru32();
            uint64_t nn  = ru64();
            scan_array(key, nat, nn, depth + 1);
        }
        return;
    }
    for (i = 0; i < n && !fail; ++i) {
        char s[8];
        switch (et) {
        case 0: case 1: case 7: rd(s, 1); break;
        case 2: case 3:         rd(s, 2); break;
        case 4: case 5: case 6: rd(s, 4); break;
        default:                rd(s, 8); break;
        }
    }
    /* record the largest flat scalar array for the manifest census */
    if (depth == 0 && et != 8 && et != 9) {
        g_arr_scalar_total += n;
        if (n > g_arr_scalar_max) {
            g_arr_scalar_max = (uint32_t)n;
            strncpy(g_biggest_key, key, sizeof(g_biggest_key) - 1);
            g_biggest_key[sizeof(g_biggest_key) - 1] = 0;
        }
    }
}

static void scan_value(const char *key, uint32_t vt, int depth) {
    switch (vt) {
    case 8: { char b[4096]; rstr(b, sizeof b);
              printf("%-56s %-7s len=%llu  %.180s\n", key, vt_name(vt),
                     (unsigned long long)strlen(b), b);
              return; }
    case 9: { uint32_t et = ru32(); uint64_t n = ru64();
              scan_array(key, et, n, depth + 1);
              printf("%-56s %-7s elem=%-7s n=%llu\n", key, vt_name(vt),
                     vt_name(et), (unsigned long long)n);
              return; }
    /* Numeric scalars are read once, into a wide union, so the printed value
     * comes from the same bytes the parser consumed. An earlier version read
     * then rewound to re-read; that double-counted bytes and produced
     * denormal garbage for f32 (5.8e-315 instead of 10000.0). */
    case 0:  { uint8_t  v; rd(&v, 1);
               printf("%-56s %-7s %u\n", key, vt_name(vt), (unsigned)v); return; }
    case 1:  { int8_t   v; rd(&v, 1);
               printf("%-56s %-7s %d\n", key, vt_name(vt), (int)v); return; }
    case 2:  { uint16_t v; rd(&v, 2);
               printf("%-56s %-7s %u\n", key, vt_name(vt), (unsigned)v); return; }
    case 3:  { int16_t  v; rd(&v, 2);
               printf("%-56s %-7s %d\n", key, vt_name(vt), (int)v); return; }
    case 4:  { uint32_t v; rd(&v, 4);
               printf("%-56s %-7s %u\n", key, vt_name(vt), (unsigned)v); return; }
    case 5:  { int32_t  v; rd(&v, 4);
               printf("%-56s %-7s %d\n", key, vt_name(vt), (int)v); return; }
    case 6:  { float    v; rd(&v, 4);
               printf("%-56s %-7s %.10g\n", key, vt_name(vt), (double)v); return; }
    case 7:  { uint8_t  v; rd(&v, 1);
               printf("%-56s %-7s %u\n", key, vt_name(vt), (unsigned)v); return; }
    case 10: { uint64_t v; rd(&v, 8);
               printf("%-56s %-7s %llu\n", key, vt_name(vt), (unsigned long long)v); return; }
    case 11: { int64_t  v; rd(&v, 8);
               printf("%-56s %-7s %lld\n", key, vt_name(vt), (long long)v); return; }
    case 12: { double   v; rd(&v, 8);
               printf("%-56s %-7s %.10g\n", key, vt_name(vt), v); return; }
    default: fail = 1; return;
    }
}

int main(int argc, char **argv) {
    char magic[4];
    uint32_t ver;
    uint64_t ntensor, nkv, i;
    uint64_t file_size, align = 32;
    long long hdr_end;

    if (argc < 2) { fprintf(stderr, "usage: nugv_kv_dump <model.gguf>\n"); return 2; }

    f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", argv[1]); return 2; }

    NUGV_SEEK(0, SEEK_END);
    file_size = (uint64_t)NUGV_TELL();
    NUGV_SEEK(0, SEEK_SET);

    rd(magic, 4);
    ver     = ru32();
    ntensor = ru64();
    nkv     = ru64();

    printf("FILE             = %s\n", argv[1]);
    printf("FILE_BYTES       = %llu\n", (unsigned long long)file_size);
    printf("GGUF_VERSION     = %u\n", ver);
    printf("TENSOR_COUNT     = %llu\n", (unsigned long long)ntensor);
    printf("KV_COUNT         = %llu\n", (unsigned long long)nkv);
    printf("\n== METADATA KEYS ==\n");
    printf("%-56s %-7s %s\n", "KEY", "TYPE", "VALUE");

    for (i = 0; i < nkv && !fail; ++i) {
        char key[512];
        uint32_t vt;
        rstr(key, sizeof key);
        vt = ru32();
        if (strcmp(key, "general.alignment") == 0 && vt == 4) {
            align = ru32();
            printf("%-56s %-7s %llu\n", key, vt_name(vt), (unsigned long long)align);
            continue;
        }
        scan_value(key, vt, 0);
    }

    hdr_end = NUGV_TELL();
    if (hdr_end < 0) hdr_end = 0;

    printf("\n== STRUCTURAL REGION ==\n");
    printf("KV_BLOCK_END           = %lld\n", hdr_end);
    printf("DATA_START             = %llu\n",
           (unsigned long long)(((uint64_t)hdr_end + align - 1) / align * align));
    printf("KV_BYTES_READ          = %llu\n", (unsigned long long)bytes_read);
    printf("MAX_OFFSET_TOUCHED     = %llu\n", (unsigned long long)max_end);
    printf("PAYLOAD_BYTES_READ     = 0\n");
    printf("STRUCTURAL_PCT_OF_FILE = %.6f%%\n",
           file_size ? 100.0 * (double)max_end / (double)file_size : 0.0);

    printf("\n== ARRAY CENSUS ==\n");
    printf("SCALAR_ARRAY_ELEMENTS_TOTAL = %llu\n", (unsigned long long)g_arr_scalar_total);
    printf("LARGEST_SCALAR_ARRAY        = %llu (key=%s)\n",
           (unsigned long long)g_arr_scalar_max, g_biggest_key);

    fclose(f);
    printf("\nVERDICT              = %s\n", fail ? "PARSE_ERROR" : "KV_DUMP_OK");
    return fail ? 1 : 0;
}