// RawrXD-Script Sample Programs
// Demonstrates language features

// ============================================================================
// Sample 1: Hello World
// ============================================================================
const char* SAMPLE_HELLO_WORLD = R"(
// Hello World - Basic output
console.log("Hello, RawrXD-Script!");
console.log("This is a sovereign JavaScript engine.");
)";

// ============================================================================
// Sample 2: Variables and Arithmetic
// ============================================================================
const char* SAMPLE_ARITHMETIC = R"(
// Variables and arithmetic
var a = 10;
var b = 20;
var sum = a + b;
var diff = a - b;
var product = a * b;
var quotient = b / a;
var remainder = b % a;

console.log("Sum: " + sum);
console.log("Difference: " + diff);
console.log("Product: " + product);
console.log("Quotient: " + quotient);
console.log("Remainder: " + remainder);
)";

// ============================================================================
// Sample 3: Control Flow
// ============================================================================
const char* SAMPLE_CONTROL_FLOW = R"(
// If statements
var x = 42;
if (x > 0) {
    console.log("x is positive");
} else if (x < 0) {
    console.log("x is negative");
} else {
    console.log("x is zero");
}

// While loop
var i = 0;
while (i < 5) {
    console.log("Loop iteration: " + i);
    i = i + 1;
}

// For loop
for (var j = 0; j < 3; j++) {
    console.log("For loop: " + j);
}
)";

// ============================================================================
// Sample 4: Functions
// ============================================================================
const char* SAMPLE_FUNCTIONS = R"(
// Function declaration
function add(a, b) {
    return a + b;
}

function multiply(a, b) {
    return a * b;
}

// Recursive function
function factorial(n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// Function calls
var result1 = add(5, 3);
var result2 = multiply(4, 7);
var result3 = factorial(5);

console.log("add(5, 3) = " + result1);
console.log("multiply(4, 7) = " + result2);
console.log("factorial(5) = " + result3);
)";

// ============================================================================
// Sample 5: Arrays
// ============================================================================
const char* SAMPLE_ARRAYS = R"(
// Array creation
var numbers = [1, 2, 3, 4, 5];
var mixed = [1, "hello", true, null];

// Array access
var first = numbers[0];
var last = numbers[4];

// Array modification
numbers[2] = 100;

// Array iteration
for (var i = 0; i < numbers.length; i++) {
    console.log("Element " + i + ": " + numbers[i]);
}

// Push elements
numbers.push(6);
numbers.push(7);

console.log("Array length: " + numbers.length);
)";

// ============================================================================
// Sample 6: Objects
// ============================================================================
const char* SAMPLE_OBJECTS = R"(
// Object creation
var person = {
    name: "Alice",
    age: 30,
    isStudent: false
};

// Property access
console.log("Name: " + person.name);
console.log("Age: " + person.age);

// Property modification
person.age = 31;
person.city = "New York";

// Computed property access
var prop = "name";
console.log("Using computed access: " + person[prop]);

// Nested objects
var company = {
    name: "RawrXD Corp",
    ceo: {
        name: "Bob",
        age: 45
    },
    employees: 100
};

console.log("CEO: " + company.ceo.name);
)";

// ============================================================================
// Sample 7: String Operations
// ============================================================================
const char* SAMPLE_STRINGS = R"(
// String concatenation
var greeting = "Hello";
var name = "World";
var message = greeting + ", " + name + "!";

console.log(message);

// String length
var text = "RawrXD";
console.log("Length of '" + text + "': " + text.length);

// String comparison
var str1 = "abc";
var str2 = "def";
if (str1 < str2) {
    console.log("str1 comes before str2");
}
)";

// ============================================================================
// Sample 8: IDE Integration
// ============================================================================
const char* SAMPLE_IDE_INTEGRATION = R"(
// File system operations
var content = fs.readFile("test.js");
if (content) {
    console.log("File content: " + content);
}

fs.writeFile("output.txt", "Hello from RawrXD!");

if (fs.exists("test.js")) {
    console.log("File exists");
}

// Workspace operations
var doc = workspace.openTextDocument("main.js");
workspace.saveAll();

// Editor operations
var text = editor.getText();
editor.setText("// New content");
editor.insertText("// Inserted", 0);

// Process operations
var output = process.exec("echo Hello");
console.log("Command output: " + output);

// Window operations
window.showInformationMessage("Build completed successfully!");
)";

// ============================================================================
// Sample 9: Fibonacci Sequence
// ============================================================================
const char* SAMPLE_FIBONACCI = R"(
// Calculate Fibonacci sequence
function fibonacci(n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Print first 10 Fibonacci numbers
console.log("Fibonacci sequence:");
for (var i = 0; i < 10; i++) {
    console.log("fib(" + i + ") = " + fibonacci(i));
}
)";

// ============================================================================
// Sample 10: Prime Numbers
// ============================================================================
const char* SAMPLE_PRIMES = R"(
// Check if a number is prime
function isPrime(n) {
    if (n <= 1) {
        return false;
    }
    if (n <= 3) {
        return true;
    }
    if (n % 2 == 0 || n % 3 == 0) {
        return false;
    }
    
    var i = 5;
    while (i * i <= n) {
        if (n % i == 0 || n % (i + 2) == 0) {
            return false;
        }
        i = i + 6;
    }
    return true;
}

// Find primes up to 50
console.log("Prime numbers up to 50:");
for (var num = 2; num <= 50; num++) {
    if (isPrime(num)) {
        console.log(num);
    }
}
)";

// ============================================================================
// Sample 11: Bubble Sort
// ============================================================================
const char* SAMPLE_BUBBLE_SORT = R"(
// Bubble sort implementation
function bubbleSort(arr) {
    var n = arr.length;
    for (var i = 0; i < n - 1; i++) {
        for (var j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                // Swap
                var temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
    return arr;
}

// Test
var numbers = [64, 34, 25, 12, 22, 11, 90];
console.log("Original: " + numbers);
bubbleSort(numbers);
console.log("Sorted: " + numbers);
)";

// ============================================================================
// Sample 12: Binary Search
// ============================================================================
const char* SAMPLE_BINARY_SEARCH = R"(
// Binary search implementation
function binarySearch(arr, target) {
    var left = 0;
    var right = arr.length - 1;
    
    while (left <= right) {
        var mid = (left + right) / 2;
        mid = mid - (mid % 1); // Floor
        
        if (arr[mid] == target) {
            return mid;
        }
        if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return -1;
}

// Test
var sorted = [2, 5, 8, 12, 16, 23, 38, 56, 72, 91];
var target = 23;
var result = binarySearch(sorted, target);

if (result != -1) {
    console.log("Found " + target + " at index " + result);
} else {
    console.log(target + " not found");
}
)";

// ============================================================================
// Sample Program Loader
// ============================================================================

#include <map>
#include <string>

struct SampleProgram {
    const char* name;
    const char* description;
    const char* source;
};

SampleProgram g_samplePrograms[] = {
    {"hello_world", "Basic output and console logging", SAMPLE_HELLO_WORLD},
    {"arithmetic", "Variables and arithmetic operations", SAMPLE_ARITHMETIC},
    {"control_flow", "If statements and loops", SAMPLE_CONTROL_FLOW},
    {"functions", "Function declarations and calls", SAMPLE_FUNCTIONS},
    {"arrays", "Array creation and manipulation", SAMPLE_ARRAYS},
    {"objects", "Object creation and property access", SAMPLE_OBJECTS},
    {"strings", "String operations", SAMPLE_STRINGS},
    {"ide_integration", "IDE API usage", SAMPLE_IDE_INTEGRATION},
    {"fibonacci", "Fibonacci sequence calculation", SAMPLE_FIBONACCI},
    {"primes", "Prime number generation", SAMPLE_PRIMES},
    {"bubble_sort", "Sorting algorithm", SAMPLE_BUBBLE_SORT},
    {"binary_search", "Search algorithm", SAMPLE_BINARY_SEARCH},
};

const int NUM_SAMPLE_PROGRAMS = sizeof(g_samplePrograms) / sizeof(g_samplePrograms[0]);

const char* GetSampleProgram(const char* name) {
    for (int i = 0; i < NUM_SAMPLE_PROGRAMS; i++) {
        if (strcmp(g_samplePrograms[i].name, name) == 0) {
            return g_samplePrograms[i].source;
        }
    }
    return nullptr;
}

void ListSamplePrograms() {
    std::cout << "Available sample programs:\n";
    for (int i = 0; i < NUM_SAMPLE_PROGRAMS; i++) {
        std::cout << "  " << g_samplePrograms[i].name << " - " 
                  << g_samplePrograms[i].description << "\n";
    }
}
