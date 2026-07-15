// Differential Test: Exceptions - Rethrow
// Tests: Re-throwing exceptions

try {
    try {
        throw "original";
    } catch (e) {
        print("caught: " + e);
        throw e;
    }
} catch (e) {
    print("re-caught: " + e);
}
