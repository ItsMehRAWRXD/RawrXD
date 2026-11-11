/* Issue #49 fixture */
#include <stdio.h>
int undeclared_fn(int a) { return a; }

int main() {
  int x = undeclared_fn(1, 2);
  printf("PASS\n");
  return 0;
}
