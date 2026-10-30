// Test 08: C and C++ interoperability
#ifdef __cplusplus
extern "C" {
#endif

int cpp_add(int a, int b);

#ifdef __cplusplus
}
#endif

int main(void) {
    return cpp_add(20, 22);  // expect 42
}
