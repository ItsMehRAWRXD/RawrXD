// DEFECT 13: Resource leak - file handle not closed
// Expected: Close file handle (RAII)
#include <iostream>
#include <fstream>
#include <string>

void writeToFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename);
    file << data;
    // BUG: file not explicitly closed, but destructor handles it
    // Actually this is fine in C++ due to RAII
    // Let's make a real resource leak - using FILE* without fclose
    FILE* f = std::fopen("leak.txt", "w");
    std::fprintf(f, "%s", data.c_str());
    // BUG: Missing fclose(f);
}

int main() {
    writeToFile("test.txt", "hello");
    // Can't easily test file handle leak in this simple test
    // Expected fix: use RAII or explicit fclose
    std::cout << "PASS" << std::endl;
    return 0;
}