#include <fstream>
#include <vector>
#include <cstdint>

int main() {
    // Simple x64 Linux shellcode that prints "Hello!" and exits
    std::vector<uint8_t> shellcode = {
        // mov rax, 1 (sys_write)
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
        // mov rdi, 1 (stdout)
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
        // lea rsi, [rip+0x21] (address of string)
        0x48, 0x8d, 0x35, 0x21, 0x00, 0x00, 0x00,
        // mov rdx, 28 (length)
        0x48, 0xc7, 0xc2, 0x1c, 0x00, 0x00, 0x00,
        // syscall
        0x0f, 0x05,
        // mov rax, 60 (sys_exit)
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
        // xor rdi, rdi
        0x48, 0x31, 0xff,
        // syscall
        0x0f, 0x05,
        // String data
        'F', 'i', 'l', 'e', 'l', 'e', 's', 's', ' ',
        'p', 'a', 'y', 'l', 'o', 'a', 'd', ' ',
        'e', 'x', 'e', 'c', 'u', 't', 'e', 'd', '!', '\n', '\0'
    };
    
    std::ofstream out("test_shellcode.bin", std::ios::binary);
    out.write(reinterpret_cast<char*>(shellcode.data()), shellcode.size());
    out.close();
    
    return 0;
}