/* 16: same source for /Od and /O2 — expect identical exit */
int main(void) {
  volatile int x = 21;
  return x + x;
}
