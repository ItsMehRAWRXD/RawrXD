// Test 06: External symbol resolution - undefined reference should fail at link
// This file references an undefined symbol that should NOT be provided
extern int undefined_symbol_xyz;
int main(void) {
    return undefined_symbol_xyz;
}
