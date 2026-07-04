// Differential Test: Loops - Continue Statement
// Tests: Skipping iterations

var sum = 0;
for (var i = 0; i < 10; i++) {
    if (i % 2 === 0) continue;
    sum = sum + i;
}
print(sum);

var count = 0;
var j = 0;
while (j < 10) {
    j = j + 1;
    if (j % 2 === 0) continue;
    count = count + 1;
}
print(count);
