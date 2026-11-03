/* 08: helper */
extern int g_seed;
int helper_fn(int x) { return x + g_seed; } /* 20+20=40; +2 in main → 42 */
