// Compiler Interface - Qt-free implementation
#include <iostream>
#include <string>

class CompilerInterface {
public:
    CompilerInterface(void* parent = nullptr) : m_parent(parent) {}
    
    bool compile(const std::string& file) {
        (void)file;
        std::cout << "Compiling..." << std::endl;
        return true;
    }
    
private:
    void* m_parent;
};

int main() {
    CompilerInterface iface;
    iface.compile("test.cpp");
    return 0;
}
