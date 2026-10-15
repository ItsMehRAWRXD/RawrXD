// H01-05: Type mismatch defect - FIXED VERSION
// DEFECT: Function signatures and variable types don't match usage
// Expected: Fix type mismatches to compile and run correctly

#include <iostream>
#include <string>
#include <vector>

// FIXED: Return type matches - returns string
std::string getMessage(int code) {
    if (code == 0) return "SUCCESS";
    return "ERROR";
}

// FIXED: Parameter type matches - accepts int
int processValue(int value) {
    return value * 2;
}

// FIXED: Vector stores int, pushes int values
std::vector<int> createNumbers() {
    std::vector<int> nums;
    nums.push_back(1);    // Fixed: int instead of string
    nums.push_back(2);    // Fixed: int instead of string
    nums.push_back(3);    // Fixed: int instead of string
    return nums;
}

// FIXED: Template works with same types
template<typename T>
T addValues(T a, T b) {
    return a + b;
}

// FIXED: Calling with matching types
void testTemplate() {
    int result = addValues(5, 10);  // Fixed: both int
    (void)result;
}

// FIXED: Struct member types match assignments
struct DataRecord {
    int id;
    std::string name;
    double value;
};

// FIXED: Assignment types match member types
void createRecord(DataRecord& rec) {
    rec.id = 123;           // Fixed: int to int
    rec.name = "456";       // Fixed: string to string
    rec.value = 789.0;      // Fixed: double to double
}

// FIXED: Function pointer type matches
using Callback = void(*)(int);
void registerCallback(Callback cb) {
    cb(42);
}

void intCallback(int value) {  // Fixed: matches Callback signature
    std::cout << value << std::endl;
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
    registerCallback(intCallback);
    
    if (allPass) {
        std::cout << "PASS" << std::endl;
        return 0;
    } else {
        return 1;
    }
}