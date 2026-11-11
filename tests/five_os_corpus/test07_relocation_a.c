// Test 07: Relocation correctness - global data access
int global_counter = 100;
int get_counter(void);
int main(void) {
    return get_counter();  // expect 100
}
