#include <iostream>
#include <cstdio>

int main(int argc, char** argv) {
    std::fprintf(stderr, "TEST: Starting program\n");
    std::fflush(stderr);
    std::printf("TEST: stdout works\n");
    std::fflush(stdout);
    std::cerr << "TEST: cerr works" << std::endl;
    return 0;
}