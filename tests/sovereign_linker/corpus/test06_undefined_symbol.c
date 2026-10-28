/* 06 negative: unresolved external must fail the link */
extern int undefined_symbol_xyz;
int main(void) { return undefined_symbol_xyz; }
