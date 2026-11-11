/* 08: C cross-ref (freestanding stand-in for C/C++ interop) */
int helper_fn(int x);
int g_seed = 20;
int main(void) { return helper_fn(g_seed) + 2; }
