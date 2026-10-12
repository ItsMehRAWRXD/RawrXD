Repo: calc.cpp in the current directory contains: a function add(a, b) that is buggy, and a main() that asserts add(2,3)==5 and returns exit code 1 when it fails.
Fix add() so it returns a + b, then compile with: cl /nologo /EHsc /O2 calc.cpp /Fe:calc.exe
Then run: calc.exe
It must print PASS. Do not change main(). When calc.exe prints PASS, reply TOOL finish.
