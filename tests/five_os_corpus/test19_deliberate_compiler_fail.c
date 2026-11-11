// Test 19: Deliberate compiler failure - invalid syntax
int main(void) {
    int x = ;  // syntax error: missing expression
    return x;
}
