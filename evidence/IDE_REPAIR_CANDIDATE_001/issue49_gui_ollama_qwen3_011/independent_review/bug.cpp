#include <cstdio>

// Issue #49 Wave2 fixture: compile-fail + arithmetic defects for recovery loop.
int undeclared_fn(int a) { return a; }
int add(int a, int b) { return a + b; }

int main() {
  (void)undeclared_fn(1);
  std::printf("AGENT_RESULT=%d\n", add(2, 3));
  return 0;
}