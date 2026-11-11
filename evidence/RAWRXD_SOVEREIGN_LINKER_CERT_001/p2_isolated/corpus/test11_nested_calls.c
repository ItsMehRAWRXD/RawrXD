/* 11: nested calls (exceptions stand-in — freestanding) */
static int leaf(int x) { return x + 1; }
static int mid(int x) { return leaf(x) + 1; }
int main(void) { return mid(40); } /* 42 */
