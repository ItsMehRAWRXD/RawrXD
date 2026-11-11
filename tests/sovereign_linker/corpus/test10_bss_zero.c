/* 10: BSS / uninitialized static (TLS stand-in until TLS supported) */
static int bss_cell;
int main(void) {
  if (bss_cell != 0) return 1;
  bss_cell = 42;
  return bss_cell;
}
