#include <cstdio>
int add_one(int x) {
  // OFF_BY_ONE: fixed
  return x + 1;
}
int main() {
  int r = add_one(41);
  if (r != 42) {
    std::printf("FAIL got=%d\n", r);
    return 1;
  }
  std::printf("PASS\n");
  return 0;
}