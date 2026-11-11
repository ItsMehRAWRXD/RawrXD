/* Deep2/REAP proxy TU B — BSS + opt-friendly arithmetic */
extern int deep2_seed;
static int bss_slot;
int reap_helper(int x) {
  if (bss_slot != 0) return 1;
  bss_slot = x + deep2_seed; /* 20+20=40 */
  return bss_slot + 2;       /* 42 */
}
