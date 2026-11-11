// REPAIR TARGET: Simple off-by-one bug in array bounds check
// File: test_repair_target.cpp
// BUG: Loop condition uses <= instead of < causing out-of-bounds access

#include <iostream>
#include <vector>

int sumArray(const std::vector<int>& arr) {
    int sum = 0;
    for (size_t i = 0; i <= arr.size(); ++i) {  // BUG: should be i < arr.size()
        sum += arr[i];
    }
    return sum;
}

int main() {
    std::vector<int> data = {1, 2, 3, 4, 5};
    int result = sumArray(data);
    std::cout << "Sum: " << result << std::endl;
    return 0;
}