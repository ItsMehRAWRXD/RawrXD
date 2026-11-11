// Differential Test: Exceptions - Nested Try Blocks
// Tests: Exception handling with nested scopes

try {
    try {
        throw "inner";
    } catch (e) {
        print("inner: " + e);
        throw "rethrown";
    }
} catch (e) {
    print("outer: " + e);
}

print("done");
