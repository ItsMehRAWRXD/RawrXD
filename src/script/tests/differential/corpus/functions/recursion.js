// Differential Test: Functions - Recursion
// Tests: Recursive function calls

function factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

print(factorial(0));
print(factorial(1));
print(factorial(5));
print(factorial(10));
