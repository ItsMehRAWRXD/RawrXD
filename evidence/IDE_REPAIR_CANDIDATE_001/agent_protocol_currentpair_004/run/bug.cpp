#include <cstdio>
int add(int a, int b) { return a + b; }
int main() { std::printf("AGENT_RESULT=%d\n", add(2, 3)); return 0; }