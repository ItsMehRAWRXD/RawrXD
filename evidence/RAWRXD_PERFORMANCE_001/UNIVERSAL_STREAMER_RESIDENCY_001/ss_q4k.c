/* ss_q4k.c — Q4_K block dequant (consume primitive, not residency) */
#include <stdint.h>
#include <string.h>
static float f16(uint16_t h)
{
    uint32_t s = (uint32_t)(h >> 15), e = (h >> 10) & 31u, m = h & 1023u, u;
    float x;
    if (e == 0) {
        if (!m) u = s << 31;
        else {
            int ee = 1;
            while ((m & 1024u) == 0) { m <<= 1; ee--; }
            m &= 1023u; u = (s << 31) | ((uint32_t)(ee + 112) << 23) | (m << 13);
        }
    } else if (e == 31) u = (s << 31) | 0x7f800000u | (m << 13);
    else u = (s << 31) | ((e + 112u) << 23) | (m << 13);
    memcpy(&x, &u, 4); return x;
}
static void scale_min(const uint8_t *s, int j, int *sc, int *mn)
{
    if (j < 4) { *sc = s[j] & 63; *mn = s[j + 4] & 63; }
    else { *sc = (s[j + 4] & 15) | ((s[j - 4] >> 6) << 4);
           *mn = (s[j + 4] >> 4) | ((s[j] >> 6) << 4); }
}
int ss_q4k_block(const uint8_t *b, float *y)
{
    uint16_t d16, m16; float d, dm; const uint8_t *sc, *q; int g, l;
    if (!b || !y) return -1;
    memcpy(&d16, b, 2); memcpy(&m16, b + 2, 2);
    d = f16(d16); dm = f16(m16); sc = b + 4; q = b + 16;
    for (g = 0; g < 8; g++) {
        int s, m, chunk = g / 2, sh = (g & 1) * 4; float ds, ms;
        scale_min(sc, g, &s, &m); ds = d * s; ms = dm * m;
        for (l = 0; l < 32; l++)
            y[g * 32 + l] = ds * ((q[chunk * 32 + l] >> sh) & 15) - ms;
    }
    return 0;
}
