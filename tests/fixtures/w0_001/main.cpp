#include <stdio.h>
int answer(void) {
    return 0; /* WRONG_LITERAL — task will demand 42 */
}
int main(void) {
    return answer() == 42 ? 0 : 1;
}
