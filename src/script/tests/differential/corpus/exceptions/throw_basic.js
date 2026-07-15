// Differential Test: Exceptions - Basic Throw/Catch
// Tests: Simple exception handling

try {
    throw 42;
} catch (e) {
    print(e);
}

try {
    throw "error message";
} catch (e) {
    print(e);
}

print("after catch");
