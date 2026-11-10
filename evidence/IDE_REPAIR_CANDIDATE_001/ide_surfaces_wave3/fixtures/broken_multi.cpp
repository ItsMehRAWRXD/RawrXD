/* Wave3 Problems fixture — intentionally broken (MSVC diagnostics). */
int undeclared_fn(int a, int b);
int main() {
  int y = undeclared_fn(1, 2);
  float f = "not_a_float";
  int *p = 0;
  return *p + y + (int)f;
}
