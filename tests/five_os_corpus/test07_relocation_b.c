// Test 07: Relocation correctness - global data access
extern int global_counter;
int get_counter(void) {
    return global_counter;
}
