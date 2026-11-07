// Standalone simulation only; not a QuickJS or IDE integration test.
#include <deque>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
struct Binding { bool active; int calls; std::string id; };
int main() {
    constexpr int count = 100000;
    std::deque<Binding> bindings;
    std::vector<Binding*> registry;
    registry.reserve(count);
    for (int i=0; i<count; ++i) {
        bindings.push_back({true, 0, std::to_string(i)});
        registry.push_back(&bindings.back());
    }
    for (int i=0; i<count; ++i) {
        auto* b=registry[i];
        if (b->id != std::to_string(i)) throw std::runtime_error("pointer invalidated");
        if (b->active) ++b->calls;
    }
    for (auto& b:bindings) b.active=false;
    for (auto* b:registry) if (b->active) ++b->calls;
    for (auto& b:bindings)
        if (b.calls != 1) throw std::runtime_error("inactive callback invoked");
    std::cout << "PASS: 100000 pointer registrations and inactive callbacks (standalone simulation)\n";
}
