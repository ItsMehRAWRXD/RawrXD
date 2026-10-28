// Test 03: Multiple translation-unit linking - file A
int add(int a, int b);
int main(void) {
    return add(21, 21);  // expect 42
}
