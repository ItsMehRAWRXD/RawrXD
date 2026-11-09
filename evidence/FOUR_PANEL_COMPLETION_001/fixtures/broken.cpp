#include <stdio.h>
int broken_fn(int x) {
  int* p = 0;
  return *p + x;
}
int main() {
  int unused;
  return broken_fn(1)
}
