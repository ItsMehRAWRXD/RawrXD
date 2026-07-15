// Differential Test: Functions - Closure Capture
// Tests: Variable capture in closures

function makeCounter() {
    var count = 0;
    return function() {
        count = count + 1;
        return count;
    };
}

var counter = makeCounter();
print(counter());
print(counter());
print(counter());

var counter2 = makeCounter();
print(counter2());
print(counter());
