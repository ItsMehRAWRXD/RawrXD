/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */
int undeclared_fn(int a) { return a; }
int main() {
  return undeclared_fn(1, 2);
}

