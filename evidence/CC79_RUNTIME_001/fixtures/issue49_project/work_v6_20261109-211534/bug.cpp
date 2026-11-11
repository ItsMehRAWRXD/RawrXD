/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */
int undeclared_fn(int a) { return a; }

int main() {
  int x = undeclared_fn(1, 2);
  return x;
}

