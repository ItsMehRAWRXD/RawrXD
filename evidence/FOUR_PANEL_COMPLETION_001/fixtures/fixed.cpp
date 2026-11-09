#include <stdio.h>
int fixed_fn(int x) { return x + 1; }
int main() {
  printf("FIXED_OK %d\n", fixed_fn(41));
  return 0;
}
