#include <cstdio>

// Issue #49 Wave2 fixture: two defects for fail-then-fix second edit.
// 1) undeclared_fn(1, 2) is a C2660 arity error (must fix call or signature).
// 2) add() returns a - b so AGENT_RESULT is wrong until changed to a + b.
// Do not leave unused parameters (C4100 under /WX).
int undeclared_fn(int a) { return a; }
int add(int a, int b) { return a - b; }

int main() {
  (void)undeclared_fn(1, 2);
  std::printf("AGENT_RESULT=%d\n", add(2, 3));
  return 0;
}