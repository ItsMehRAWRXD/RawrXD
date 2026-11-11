#include <stdio.h>
int main() {
    FILE *fp = fopen("d:\\ministral3_q4_0.gguf", "rb");
    if (!fp) {
        perror("fopen failed");
        return 1;
    }
    printf("File opened successfully\n");
    fclose(fp);
    return 0;
}
