// Differential Test: Exceptions - Finally Block
// Tests: finally execution with and without exceptions

var x = 0;

try {
    x = 1;
} finally {
    x = 2;
}
print(x);

try {
    throw "error";
} catch (e) {
    x = 3;
} finally {
    x = 4;
}
print(x);
