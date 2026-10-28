/* Deep2/REAP proxy TU A — multi-object + initialized data (not native Deep2 objs) */
extern int reap_helper(int);
int deep2_seed = 20;
int main(void) { return reap_helper(deep2_seed); }
