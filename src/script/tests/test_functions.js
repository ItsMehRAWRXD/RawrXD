// RawrXD-Script Sample: Functions
// Tests function declarations, calls, and closures

// Simple function
function add(a, b) {
    return a + b;
}

// Function with multiple statements
function factorial(n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// Function expression
var multiply = function(x, y) {
    return x * y;
};

// Named function expression
var divide = function div(x, y) {
    if (y === 0) {
        throw new Error("Division by zero");
    }
    return x / y;
};

// Closure example
function makeCounter() {
    var count = 0;
    return function() {
        return ++count;
    };
}

// Higher-order function
function applyOperation(a, b, operation) {
    return operation(a, b);
}

// Arrow-like function (using function expression)
var square = function(x) {
    return x * x;
};

// Test calls
var result1 = add(5, 3);
var result2 = factorial(5);
var result3 = multiply(4, 7);
var result4 = applyOperation(10, 20, add);
var result5 = applyOperation(10, 20, multiply);

var counter = makeCounter();
var c1 = counter();
var c2 = counter();
var c3 = counter();

console.log("Results:", result1, result2, result3, result4, result5);
console.log("Counter:", c1, c2, c3);
