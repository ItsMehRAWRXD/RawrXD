// DEFECT 02: Null pointer dereference
// Expected: Add null check before dereferencing
#include <iostream>
#include <string>

struct Node {
    int value;
    Node* next;
    Node(int v) : value(v), next(nullptr) {}
};

int getValue(Node* node) {
    // BUG: No null check
    return node->value;
}

int main() {
    Node* head = nullptr;
    int result = getValue(head);
    
    if (result == -1) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected -1 for null, got " << result << std::endl;
        return 1;
    }
}