/* g3_wake_lease_util.cpp — NameHas (≤99). */
#include <cstring>

int NameHas(const char* hay, const char* n) {
    if (!hay || !n) return 0;
    size_t N = std::strlen(n);
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (p[i] && i < N) {
            char a = p[i], b = n[i];
            if (a >= 'a' && a <= 'z') a = (char)(a - 32);
            if (b >= 'a' && b <= 'z') b = (char)(b - 32);
            if (a != b) break;
            ++i;
        }
        if (i == N) return 1;
    }
    return 0;
}
