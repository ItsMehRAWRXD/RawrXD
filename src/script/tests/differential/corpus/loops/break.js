// Differential Test: Loops - Break Statement
// Tests: Breaking out of loops

var sum = 0;
for (var i = 0; i < 100; i++) {
    if (i > 5) break;
    sum = sum + i;
}
print(sum);

var j = 0;
while (true) {
    if (j >= 3) break;
    j = j + 1;
}
print(j);
