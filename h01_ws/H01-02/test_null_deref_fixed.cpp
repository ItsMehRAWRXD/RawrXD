// H01-02: Null pointer dereference defect - FIXED VERSION
// DEFECT: Function dereferences pointer without null check
// Expected: Add null validation and return error code

#include <iostream>
#include <string>
#include <cstring>

struct StringProcessor {
    // FIXED: Check for null before dereferencing
    static int processString(const char* ptr, std::string& output) {
        if (ptr == nullptr) {
            return -1;  // Error code for null pointer
        }
        output = std::string(ptr);
        return 0;
    }
    
    // FIXED: Check for null before dereferencing
    static int getLength(const char* ptr) {
        if (ptr == nullptr) {
            return 0;  // Return 0 for null pointer
        }
        return std::strlen(ptr);
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