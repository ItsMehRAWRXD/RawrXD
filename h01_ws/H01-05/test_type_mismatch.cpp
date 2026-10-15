// H01-05: Type mismatch defect
// DEFECT: Function signatures and variable types don't match usage
// Expected: Fix type mismatches to compile and run correctly

#include <iostream>
#include <string>
#include <vector>

// BUG: Return type mismatch - declared int but returns string
std::string getMessage(int code) {
    if (code == 0) return "SUCCESS";
    return "ERROR";
}

// BUG: Parameter type mismatch - expects int but passes string
int processValue(int value) {
    return value * 2;
}

// BUG: Vector type mismatch - stores int but pushes strings
std::vector<int> createNumbers() {
    std::vector<int> nums;
    nums.push_back("one");    // Type mismatch
    nums.push_back("two");    // Type mismatch
    nums.push_back("three");  // Type mismatch
    return nums;
}

// BUG: Template type deduction failure
template<typename T>
T addValues(T a, T b) {
    return a + b;
}

// BUG: Calling with mismatched types
void testTemplate() {
    int result = addValues(5, "hello");  // Type mismatch
    (void)result;
}

// BUG: Struct member type mismatch
struct DataRecord {
    int id;
    std::string name;
    double value;
};

// BUG: Assignment type mismatch
void createRecord(DataRecord& rec) {
    rec.id = "123";        // Type mismatch: string to int
    rec.name = 456;        // Type mismatch: int to string
    rec.value = "789.0";   // Type mismatch: string to double
}

// BUG: Function pointer type mismatch
using Callback = void(*)(int);
void registerCallback(Callback cb) {
    cb(42);
}

void stringCallback(std::string s) {  // Wrong signature
    std::cout << s << std::endl;
}

int main() {
    bool allPass = true;
    
    // Test 1: Return type fix - should return string
    std::string msg = getMessage(0);
    if (msg != "SUCCESS") {
        std::cout << "FAIL: getMessage(0) = " << msg << std::endl;
        allPass = false;
    }
    
    // Test 2: Parameter type fix - processValue should accept int
    int doubled = processValue(21);
    if (doubled != 42) {
        std::cout << "FAIL: processValue(21) = " << doubled << std::endl;
        allPass = false;
    }
    
    // Test 3: Vector type fix - should store ints
    std::vector<int> nums = createNumbers();
    if (nums.size() != 3 || nums[0] != 1 || nums[1] != 2 || nums[2] != 3) {
        std::cout << "FAIL: createNumbers() returned wrong values" << std::endl;
        allPass = false;
    }
    
    // Test 4: Template should work with same types
    int sum = addValues(10, 20);
    if (sum != 30) {
        std::cout << "FAIL: addValues(10,20) = " << sum << std::endl;
        allPass = false;
    }
    
    // Test 5: Struct member types
    DataRecord rec;
    createRecord(rec);
    if (rec.id != 123 || rec.name != "456" || rec.value != 789.0) {
        std::cout << "FAIL: DataRecord has wrong values: id=" << rec.id 
                  << " name=" << rec.name << " value=" << rec.value << std::endl;
        allPass = false;
    }
    
    // Test 6: Callback type - this should compile and work with correct signature
    // (This test just verifies the signature matches, not that it's called)
    
    if (allPass) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        return 1;
    }
}