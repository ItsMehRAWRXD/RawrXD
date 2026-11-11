/* Issue #49 second-edit fixture: reintroduced arity bug after first repair. */
#include <stdio.h>
int undeclared_fn(int a) { return a; }
int main() {
  int x = undeclared_fn(1, 2);
  printf("PASS\n");
  return 0;
}

