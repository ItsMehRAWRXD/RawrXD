// RawrXD-Script Sample: Control Flow
// Tests if/else, loops, switch, try/catch

// If-else
function testIfElse(x) {
    if (x > 0) {
        return "positive";
    } else if (x < 0) {
        return "negative";
    } else {
        return "zero";
    }
}

// While loop
function testWhile(n) {
    var sum = 0;
    var i = 1;
    while (i <= n) {
        sum = sum + i;
        i++;
    }
    return sum;
}

// For loop
function testFor(arr) {
    var sum = 0;
    for (var i = 0; i < arr.length; i++) {
        sum = sum + arr[i];
    }
    return sum;
}

// Do-while (simulated with while)
function testDoWhile() {
    var count = 0;
    var i = 0;
    while (true) {
        count = count + i;
        i++;
        if (i >= 5) break;
    }
    return count;
}

// Switch statement
function testSwitch(day) {
    switch (day) {
        case 1:
            return "Monday";
        case 2:
            return "Tuesday";
        case 3:
            return "Wednesday";
        case 4:
            return "Thursday";
        case 5:
            return "Friday";
        case 6:
        case 7:
            return "Weekend";
        default:
            return "Invalid day";
    }
}

// Try-catch
function testTryCatch() {
    try {
        var result = riskyOperation();
        return result;
    } catch (e) {
        return "Error caught: " + e.message;
    } finally {
        console.log("Finally block executed");
    }
}

// Break and continue
function testBreakContinue() {
    var result = [];
    for (var i = 0; i < 10; i++) {
        if (i === 3) continue;
        if (i === 7) break;
        result.push(i);
    }
    return result;
}

// Ternary operator
function testTernary(x) {
    return x > 0 ? "positive" : x < 0 ? "negative" : "zero";
}

// Logical operators short-circuit
function testShortCircuit() {
    var a = null;
    var b = a && a.value;  // Should short-circuit
    var c = a || "default"; // Should return "default"
    return { b: b, c: c };
}

console.log("Control flow tests complete");
