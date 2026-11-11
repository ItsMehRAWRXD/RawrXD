/* 17: sum 0..99 = 4950 (ExitProcess accepts full DWORD) */
int main(void) {
  int sum = 0;
  for (int i = 0; i < 100; i++) sum += i;
  return sum;
}
