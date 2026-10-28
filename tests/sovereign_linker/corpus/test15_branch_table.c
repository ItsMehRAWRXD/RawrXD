/* 15: branch-heavy path */
int main(void) {
  int v = 0;
  for (int i = 0; i < 7; i++) v += 6;
  return v; /* 42 */
}
