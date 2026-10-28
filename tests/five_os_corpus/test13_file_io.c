// Test 13: File I/O
#include <stdio.h>
int main(void) {
    FILE* f = fopen("test13_output.txt", "w");
    if (!f) return 1;
    fprintf(f, "file_io_ok\n");
    fclose(f);
    return 0;
}
