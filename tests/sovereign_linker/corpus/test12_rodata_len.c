/* 12: rodata / string-literal length (stdlib stand-in) */
int main(void) {
  const char *s = "hello";
  int n = 0;
  while (s[n]) n++;
  return n; /* expect 5 */
}
