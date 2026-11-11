#include <string>

std::string greet(const std::string& name) {
    return "Hello, " + name;
}

int main() {
    return greet("RawrXD").empty() ? 1 : 0;
}
