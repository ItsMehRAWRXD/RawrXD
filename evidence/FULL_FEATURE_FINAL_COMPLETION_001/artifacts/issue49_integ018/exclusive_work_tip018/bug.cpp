/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.
 * Do not pre-fix - agent (or measured blocker) must own the repair.
 */
int undeclared_fn(int a);

int main() {
  int x = undeclared_fn(1, 2);
  return x;
}
