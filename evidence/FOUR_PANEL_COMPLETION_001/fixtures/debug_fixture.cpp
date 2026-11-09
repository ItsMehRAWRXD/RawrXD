#include <stdio.h>
volatile int g_watch = 7;
int main() {
  int local = 42;
  g_watch = local + 1;
  printf("DEBUG_FIXTURE_OK watch=%d local=%d\n", g_watch, local);
  return 0;
}
