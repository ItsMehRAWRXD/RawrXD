.code
EXTERNDEF ExitProcess:PROC
EXTERNDEF GetStdHandle:PROC
EXTERNDEF WriteFile:PROC

_start:
    xor rax, rax
    ret
END
