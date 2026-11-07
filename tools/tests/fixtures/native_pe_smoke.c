/* Minimal freestanding PE/COFF x64 fixture with an explicit main entry.
 * It intentionally avoids CRT/Windows SDK imports: structural link smoke only.
 * Returning from main without a CRT startup is not an OS runtime test. */
int main(void) { return 42; }
