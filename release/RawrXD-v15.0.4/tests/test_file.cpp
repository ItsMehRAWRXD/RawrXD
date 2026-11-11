#include <iostream>
#include <fstream>

int main() {
    std::ifstream file("D:\\ministral3_q4_0.gguf", std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }
    auto size = file.tellg();
    std::cout << "File size: " << size << std::endl;
    file.seekg(0, std::ios::beg);
    char buffer[4];
    if (file.read(buffer, 4)) {
        std::cout << "First 4 bytes: ";
        for (int i = 0; i < 4; i++) {
            std::cout << std::hex << (unsigned char)buffer[i] << " ";
        }
        std::cout << std::dec << std::endl;
    }
    return 0;
}
