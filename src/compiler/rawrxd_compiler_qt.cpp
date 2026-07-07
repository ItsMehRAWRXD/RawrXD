// RawrXD Compiler - Qt-free implementation
#include <iostream>
#include <string>

namespace RawrXD {
namespace Compiler {

class CompilerWidget {
public:
    CompilerWidget(void* parent = nullptr) : m_parent(parent) {}
    void initialize() {
        std::cout << "Compiler widget initialized" << std::endl;
    }
private:
    void* m_parent;
};

} // namespace Compiler
} // namespace RawrXD

int main() {
    RawrXD::Compiler::CompilerWidget widget;
    widget.initialize();
    return 0;
}
