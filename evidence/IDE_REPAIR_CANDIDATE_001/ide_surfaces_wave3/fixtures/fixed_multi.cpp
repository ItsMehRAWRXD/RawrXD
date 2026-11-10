/* Wave3 Problems fixture — compile-clean twin. */
int undeclared_fn(int a, int b);
int main() {
  int y = 1;
  int x = y;
  undeclared_fn(1, 2);
  float f = 1.0f;
  return x + (int)f;
}
int undeclared_fn(int a, int b) { return a + b; }
