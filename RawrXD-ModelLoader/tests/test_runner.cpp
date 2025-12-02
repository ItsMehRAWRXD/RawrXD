#include <iostream>
// Forward declarations
int RunBaselineTest();
int RunPidTest();

int main() {
    int rc = RunBaselineTest();
    if (rc != 0) { std::cerr << "RunBaselineTest failed: " << rc << std::endl; return rc; }
    rc = RunPidTest();
    if (rc != 0) { std::cerr << "RunPidTest failed: " << rc << std::endl; return rc; }
    std::cout << "All tests passed" << std::endl;
    return 0;
}
#include <iostream>
// Forward declarations from test files
int RunBaselineTest();
int RunPidTest();

int main() {
    int rc = RunBaselineTest();
    if (rc != 0) { std::cerr << "RunBaselineTest failed: " << rc << std::endl; return rc; }
    rc = RunPidTest();
    if (rc != 0) { std::cerr << "RunPidTest failed: " << rc << std::endl; return rc; }
    std::cout << "All tests passed" << std::endl;
    return 0;
}
#include <iostream>

extern int TestBaseline();
extern int TestPid();

int main(int argc, char** argv) {
    int rc = TestBaseline();
    if (rc != 0) { std::cerr << "Baseline test failed: " << rc << std::endl; return rc; }
    rc = TestPid();
    if (rc != 0) { std::cerr << "PID test failed: " << rc << std::endl; return rc; }
    std::cout << "All tests passed\n";
    return 0;
}
