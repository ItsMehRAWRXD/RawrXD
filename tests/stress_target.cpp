// stress_target.cpp
// Simple target for debugger stress testing
// Compile: cl /Zi /Od /Fe:stress_target.exe stress_target.cpp

int main() {
    int counter = 0;
    // Set breakpoint on the line below
    for (int i = 0; i < 100000; i++) {
        counter += i;  // BREAKPOINT HERE
    }
    return counter;
}
