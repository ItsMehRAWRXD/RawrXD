// Test 12: Standard library usage
#include <vector>
#include <string>
#include <iostream>
int main(void) {
    std::vector<int> v = {1, 2, 3, 4, 5};
    std::string s = "hello";
    std::cout << "size=" << v.size() << " str=" << s << "\n";
    return 0;
}
