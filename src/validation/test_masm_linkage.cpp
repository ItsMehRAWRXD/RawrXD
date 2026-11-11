// Simple test to verify MASM linkage works
#include <iostream>

// Direct declaration - function is extern "C" not in namespace
extern "C" int MASM_Test_Minimal();

int main() {
    std::cout << "Testing MASM linkage..." << std::endl;
    
    // Test the minimal function
    int result = MASM_Test_Minimal();
    std::cout << "MASM_Test_Minimal returned: " << result << std::endl;
    
    if (result == 0) {
        std::cout << "SUCCESS: MASM linkage works!" << std::endl;
        return 0;
    } else {
        std::cout << "FAILED: Unexpected return value" << std::endl;
        return 1;
    }
}
