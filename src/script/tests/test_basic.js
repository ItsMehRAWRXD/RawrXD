// RawrXD-Script Sample: Basic Expressions and Variables
// This file tests the basic language features

// Variable declarations
var x = 10;
let y = 20;
const z = 30;

// Arithmetic expressions
var sum = x + y + z;
var product = x * y * z;
var difference = z - y;
var quotient = z / x;
var remainder = z % x;

// String concatenation
var greeting = "Hello";
var name = "World";
var message = greeting + ", " + name + "!";

// Boolean logic
var a = true;
var b = false;
var andResult = a && b;
var orResult = a || b;
var notResult = !a;

// Comparison operators
var eq = x == y;
var neq = x != y;
var lt = x < y;
var gt = x > y;
var lte = x <= y;
var gte = x >= y;

// Update expressions
x++;
y--;
++x;
--y;

// Print results (will be native bridge call)
console.log("Sum:", sum);
console.log("Product:", product);
console.log("Message:", message);
