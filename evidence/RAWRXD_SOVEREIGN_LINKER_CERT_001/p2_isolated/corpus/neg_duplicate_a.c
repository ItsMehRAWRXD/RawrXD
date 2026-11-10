/* Negative: duplicate strong symbol — definition A */
int conflict(void) { return 1; }
int main(void) { return conflict(); }
