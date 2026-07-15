#include <stdio.h>

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    printf("Hello from test program\n");
    fprintf(stderr, "Hello from stderr\n");
    return 0;
}
