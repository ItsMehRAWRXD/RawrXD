// REAL DEFECT: Off-by-one error in array bounds
// File: test_real_repair.cpp
// BUG: Loop uses <= instead of < causing out-of-bounds access on last iteration

#include <iostream>
#include <vector>
#include <string>

struct ArrayProcessor {
    std::vector<int> data;
    
    ArrayProcessor(const std::vector<int>& input) : data(input) {}
    
    // BUG: Should be i < data.size(), not i <= data.size()
    int computeSum() const {
        int sum = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            sum += data[i];  // Out of bounds on last iteration
        }
        return sum;
    }
    
    // BUG: Same off-by-one error
    std::string toString() const {
        std::string result = "[";
        for (size_t i = 0; i < data.size(); ++i) {
            result += std::to_string(data[i]);
            if (i < data.size()) result += ", ";
        }
        result += "]";
        return result;
    }
};

int main() {
    std::vector<int> testData = {10, 20, 30, 40, 50};
    ArrayProcessor processor(testData);
    
    std::cout << "Data: " << processor.toString() << std::endl;
    std::cout << "Sum: " << processor.computeSum() << std::endl;
    
    // Expected sum: 150
    // Expected string: [10, 20, 30, 40, 50]
    
    int expectedSum = 150;
    int actualSum = processor.computeSum();
    
    if (actualSum == expectedSum) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        std::cout << "FAIL: Expected " << expectedSum << ", got " << actualSum << std::endl;
        return 1;
    }
}