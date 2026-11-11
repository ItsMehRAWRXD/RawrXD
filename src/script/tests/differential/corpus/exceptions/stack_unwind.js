// Differential Test: Exceptions - Stack Unwinding
// Tests: Proper stack cleanup during exception unwinding

function level3() {
    throw "deep error";
}

function level2() {
    level3();
    print("should not reach");
}

function level1() {
    level2();
    print("should not reach");
}

try {
    level1();
} catch (e) {
    print(e);
}

print("recovered");
