/* Issue #49 second-edit fixture: reintroduced arity bug after first repair. */
#include <stdio.h>
int undeclared_fn(int a) { return a; }
int main() {
  int x = undeclared_fn(1, 2);
  char p[5]; p[0]=80; p[1]=65; p[2]=83; p[3]=83; p[4]=0; puts(p);
  return 0;
}
