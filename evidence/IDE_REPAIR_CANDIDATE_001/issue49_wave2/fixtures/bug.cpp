/* Issue #49 Wave2 fixture: intentional arity bug for agent fix loop.
 * Same shape as CC79 issue49_project — Wave2 copy so Wave1 paths stay untouched. */
int undeclared_fn(int a) { return a; }
int main() {
  return undeclared_fn(1, 2);
}
