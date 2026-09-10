/* test_TokenK3C_kn.c — TOKEN<-->K3-C three RE smokes. DEPS=0 PRODUCT_WIRE=0 */
#include <stdio.h>

typedef struct { unsigned remain; unsigned last; } K3CState;

extern unsigned TokenK3C_RE1(unsigned, K3CState*, unsigned*, K3CState*);
extern unsigned TokenK3C_RE2(unsigned, K3CState*, unsigned*, K3CState*);
extern unsigned TokenK3C_RE3(unsigned, K3CState*, unsigned*, K3CState*);

int main(void) {
    K3CState st = {8u, 0u};
    unsigned o1 = 0u, o2 = 0u;
    unsigned a = TokenK3C_RE1(0u, &st, &o1, 0);
    unsigned b = TokenK3C_RE2(0u, &st, &o2, 0);
    unsigned t = 0u, c = 0u;
    st.remain = 8u;
    for (;;) {
        c = TokenK3C_RE3(t, 0, 0, 0);
        t = c;
        if (t >= 8u) break;
    }
    printf("KN_O3KKEN=1 RE1_EXEC=%u RE2_OWN=%u RE3_ELIM=%u\n", a, b, c);
    return (a == 1u && b == 1u && c == 8u) ? 0 : 1;
}
