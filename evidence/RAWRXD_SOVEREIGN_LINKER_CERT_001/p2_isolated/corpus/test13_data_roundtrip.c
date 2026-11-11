/* 13: data write/read roundtrip (file I/O stand-in) */
static int slot;
int main(void) {
  slot = 42;
  if (slot != 42) return 1;
  return 0;
}
