; Test multiple API calls
sub rsp, 40

; Get stdout
mov rcx, -11
call GetStdHandle

; Exit
mov rcx, 0
call ExitProcess
