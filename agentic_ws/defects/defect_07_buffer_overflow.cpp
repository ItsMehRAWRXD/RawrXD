// DEFECT 07: Buffer overflow - writing past array end
// Expected: Fix bounds check
#include <iostream>
#include <cstring>

void copyData(char* dest, size_t destSize, const char* src) {
    // BUG: No bounds check, can overflow dest
    std::strcpy(dest, src);
}

int main() {
    char buffer[10];
    const char* longString = "This string is way too long for the buffer";
    
    copyData(buffer, 10, longString);
    
    if (std::strcmp(buffer, "This strin") == 0) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Buffer overflow or incorrect copy" << std::endl;
        return 1;
    }
}