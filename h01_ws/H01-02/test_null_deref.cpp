// H01-02: Null pointer dereference defect
// DEFECT: Function dereferences pointer without null check
// Expected: Add null validation and return error code

#include <iostream>
#include <string>

struct StringProcessor {
    // BUG: Dereferences ptr without checking for null
    static int processString(const char* ptr, std::string& output) {
        output = std::string(ptr);  // Crash if ptr is null
        return 0;
    }
    
    // BUG: Same issue
    static int getLength(const char* ptr) {
        return std::strlen(ptr);  // Crash if ptr is null
    }
};

int main() {
    // Test 1: Valid string
    const char* validStr = "hello world";
    std::string output;
    int result1 = StringProcessor::processString(validStr, output);
    int len1 = StringProcessor::getLength(validStr);
    
    // Test 2: Null pointer - should not crash
    const char* nullStr = nullptr;
    int result2 = StringProcessor::processString(nullStr, output);
    int len2 = StringProcessor::getLength(nullStr);
    
    // Expected: Both calls with null should return error code, not crash
    // Valid string should work correctly
    
    bool validWorks = (result1 == 0 && output == "hello world" && len1 == 11);
    bool nullSafe = (result2 != 0 && len2 == 0);  // Error code for null
    
    if (validWorks && nullSafe) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: validWorks=" << validWorks << " nullSafe=" << nullSafe << std::endl;
        return 1;
    }
}