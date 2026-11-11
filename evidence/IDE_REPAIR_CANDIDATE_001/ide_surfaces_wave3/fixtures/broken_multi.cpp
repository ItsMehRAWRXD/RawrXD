int undeclared_fn();
int main() {
  int x = y;
  undeclared_fn(1,2);
  float f = "nope";
  return x;
}
