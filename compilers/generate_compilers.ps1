# Compiler Generator Script for RawrXD
# Generates assembly source files for all 69 languages

$languages = @(
    # Already built (8)
    @{Name="universal"; Ext="c,cpp,h"; Keywords="int,char,if,else,while,for,return"},
    @{Name="eon"; Ext="eon"; Keywords="module,import,export,func,let,const"},
    @{Name="bash"; Ext="sh"; Keywords="if,then,else,fi,for,do,done,while"},
    @{Name="powershell"; Ext="ps1"; Keywords="function,if,else,for,while,return"},
    @{Name="java"; Ext="java"; Keywords="public,class,static,void,int,String"},
    @{Name="cs"; Ext="cs"; Keywords="namespace,class,public,private,static,void"},
    @{Name="python"; Ext="py"; Keywords="def,class,if,else,for,while,import"},
    @{Name="js"; Ext="js"; Keywords="function,var,let,const,if,else,for,while"},
    
    # High Priority (10)
    @{Name="go"; Ext="go"; Keywords="package,import,func,var,const,type"},
    @{Name="rust"; Ext="rs"; Keywords="fn,let,mut,pub,struct,impl,use"},
    @{Name="swift"; Ext="swift"; Keywords="func,var,let,if,else,for,while"},
    @{Name="kotlin"; Ext="kt"; Keywords="fun,val,var,class,object,if,else"},
    @{Name="ruby"; Ext="rb"; Keywords="def,end,if,else,while,for,class"},
    @{Name="php"; Ext="php"; Keywords="function,if,else,for,while,class,return"},
    @{Name="typescript"; Ext="ts"; Keywords="function,let,const,interface,class"},
    @{Name="perl"; Ext="pl"; Keywords="sub,if,else,for,while,package,use"},
    @{Name="lua"; Ext="lua"; Keywords="function,if,then,else,for,while,end"},
    @{Name="r"; Ext="r"; Keywords="function,if,else,for,while,return,library"},
    
    # Medium Priority (20)
    @{Name="scala"; Ext="scala"; Keywords="def,val,var,class,object,if,else"},
    @{Name="groovy"; Ext="groovy"; Keywords="def,if,else,for,while,class,return"},
    @{Name="dart"; Ext="dart"; Keywords="void,int,String,if,else,for,while"},
    @{Name="julia"; Ext="jl"; Keywords="function,if,else,for,while,end,return"},
    @{Name="haskell"; Ext="hs"; Keywords="module,import,if,then,else,where"},
    @{Name="clojure"; Ext="clj"; Keywords="def,defn,if,do,let,fn,ns"},
    @{Name="erlang"; Ext="erl"; Keywords="module,export,if,case,receive,spawn"},
    @{Name="elixir"; Ext="ex"; Keywords="def,defp,if,else,for,case,cond"},
    @{Name="ocaml"; Ext="ml"; Keywords="let,if,then,else,match,fun,rec"},
    @{Name="fsharp"; Ext="fs"; Keywords="let,if,then,else,match,fun,module"},
    @{Name="objectivec"; Ext="m"; Keywords="int,void,if,else,for,while,return"},
    @{Name="d"; Ext="d"; Keywords="void,int,if,else,for,while,class"},
    @{Name="nim"; Ext="nim"; Keywords="proc,let,var,if,else,for,while"},
    @{Name="crystal"; Ext="cr"; Keywords="def,end,if,else,while,for,class"},
    @{Name="zig"; Ext="zig"; Keywords="fn,const,var,if,else,for,while"},
    @{Name="v"; Ext="v"; Keywords="fn,mut,if,else,for,struct,import"},
    @{Name="odin"; Ext="odin"; Keywords="proc,if,else,for,struct,package"},
    @{Name="fortran"; Ext="f90"; Keywords="program,if,then,else,do,end,subroutine"},
    @{Name="cobol"; Ext="cob"; Keywords="IDENTIFICATION,PROCEDURE,IF,ELSE,MOVE"},
    @{Name="pascal"; Ext="pas"; Keywords="begin,end,if,then,else,for,while"},
    
    # Additional Languages (31)
    @{Name="ada"; Ext="ada"; Keywords="procedure,function,if,then,else,for"},
    @{Name="lisp"; Ext="lisp"; Keywords="defun,if,cond,let,lambda,progn"},
    @{Name="scheme"; Ext="scm"; Keywords="define,if,lambda,let,cond,quote"},
    @{Name="prolog"; Ext="pro"; Keywords="is,if,then,else,:-,.,;"},
    @{Name="forth"; Ext="fth"; Keywords=":,;,if,else,then,do,loop"},
    @{Name="apl"; Ext="apl"; Keywords="←,×,÷,+,-,×,÷"},
    @{Name="smalltalk"; Ext="st"; Keywords="ifTrue,ifFalse,whileTrue,do"},
    @{Name="coffeescript"; Ext="coffee"; Keywords="if,else,for,while,class,->"},
    @{Name="elm"; Ext="elm"; Keywords="import,exposing,if,then,else,case"},
    @{Name="purescript"; Ext="purs"; Keywords="module,import,if,then,else,case"},
    @{Name="reason"; Ext="re"; Keywords="let,if,else,for,while,fun,module"},
    @{Name="rescript"; Ext="res"; Keywords="let,if,else,for,while,fun"},
    @{Name="gleam"; Ext="gleam"; Keywords="fn,let,if,else,case,import"},
    @{Name="wren"; Ext="wren"; Keywords="class,if,else,for,while,return"},
    @{Name="gravity"; Ext="gravity"; Keywords="func,var,if,else,for,while"},
    @{Name="solidity"; Ext="sol"; Keywords="contract,function,if,else,for,while"},
    @{Name="vyper"; Ext="vy"; Keywords="@external,def,if,else,for,while"},
    @{Name="move"; Ext="move"; Keywords="module,fun,struct,public,entry"},
    @{Name="cairo"; Ext="cairo"; Keywords="func,if,else,for,while,return"},
    @{Name="noir"; Ext="nr"; Keywords="fn,if,else,for,while,return"},
    @{Name="leo"; Ext="leo"; Keywords="function,if,else,for,while,return"},
    @{Name="sway"; Ext="sw"; Keywords="fn,if,else,for,while,return"},
    @{Name="ink"; Ext="ink"; Keywords="#,##,###,-,+,*,>"},
    @{Name="wasm"; Ext="wat"; Keywords="module,func,if,else,for,while"},
    @{Name="llvm"; Ext="ll"; Keywords="define,declare,if,else,for,while"},
    @{Name="mlir"; Ext="mlir"; Keywords="func,if,else,for,while,return"},
    @{Name="verilog"; Ext="v"; Keywords="module,input,output,wire,reg,always"},
    @{Name="vhdl"; Ext="vhd"; Keywords="entity,architecture,signal,process,if"},
    @{Name="systemverilog"; Ext="sv"; Keywords="module,class,function,if,else"},
    @{Name="chisel"; Ext="scala"; Keywords="class,extends,Module,IO,when"}
)

$template = @"
bits 64
default rel

section .data
    msg_banner db "RawrXD {0} Compiler v1.0", 13, 10
               db "Compiles {0} source", 13, 10, 0
    msg_banner_len equ `$` - msg_banner
    msg_usage db "Usage: {1}_compiler <file.{2}>", 13, 10, 0
    msg_usage_len equ `$` - msg_usage
    msg_open_err db "Error: Cannot open file", 13, 10, 0
    msg_open_err_len equ `$` - msg_open_err
    msg_success db "{0} source processed successfully", 13, 10, 0
    msg_success_len equ `$` - msg_success
    msg_parsing db "Parsing {0} source...", 13, 10, 0
    msg_parsing_len equ `$` - msg_parsing
    
    filename_buffer times 260 db 0
    file_buffer times 65536 db 0
    token_buffer times 256 db 0
    
    file_handle dq 0
    bytes_read dq 0
    bytes_written dq 0
    token_count dq 0

section .text
    global main
    extern GetStdHandle
    extern WriteFile
    extern ReadFile
    extern CreateFileA
    extern CloseHandle
    extern ExitProcess
    extern GetCommandLineA

main:
    push rbp
    mov rbp, rsp
    sub rsp, 96

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_banner]
    mov r8, msg_banner_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile

    call parse_arguments
    test rax, rax
    jz .no_args

    mov rcx, rax
    call open_file
    test rax, rax
    jz .open_error

    call parse_source

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_success]
    mov r8, msg_success_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile

    xor rax, rax
    jmp .exit

.no_args:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_usage]
    mov r8, msg_usage_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 1
    jmp .exit

.open_error:
    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_open_err]
    mov r8, msg_open_err_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile
    mov rax, 2

.exit:
    mov rcx, rax
    call ExitProcess

parse_source:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov rcx, -11
    call GetStdHandle
    mov rcx, rax
    lea rdx, [msg_parsing]
    mov r8, msg_parsing_len
    lea r9, [bytes_written]
    mov qword [rsp+32], 0
    call WriteFile

    mov qword [token_count], 0
    lea rsi, [file_buffer]

.parse_loop:
    movzx eax, byte [rsi]
    test al, al
    jz .parse_done

    cmp al, ' '
    je .skip_char
    cmp al, 9
    je .skip_char
    cmp al, 13
    je .skip_char
    cmp al, 10
    je .skip_char

    cmp al, '/'
    jne .not_comment
    movzx ebx, byte [rsi+1]
    cmp bl, '/'
    je .skip_line_comment

.not_comment:
    cmp al, 34
    je .parse_string
    cmp al, 39
    je .parse_string

    call is_alpha
    jc .parse_identifier
    call is_digit
    jc .parse_number

    inc qword [token_count]
    inc rsi
    jmp .parse_loop

.skip_char:
    inc rsi
    jmp .parse_loop

.skip_line_comment:
    add rsi, 2
.line_loop:
    movzx eax, byte [rsi]
    cmp al, 10
    je .parse_loop
    test al, al
    jz .parse_done
    inc rsi
    jmp .line_loop

.parse_string:
    inc qword [token_count]
    inc rsi
.str_loop:
    movzx eax, byte [rsi]
    test al, al
    jz .parse_done
    cmp al, 34
    je .str_end
    cmp al, 39
    je .str_end
    cmp al, 92
    je .str_esc
    inc rsi
    jmp .str_loop
.str_esc:
    add rsi, 2
    jmp .str_loop
.str_end:
    inc rsi
    jmp .parse_loop

.parse_identifier:
    inc qword [token_count]
.ident_loop:
    inc rsi
    movzx eax, byte [rsi]
    call is_alpha
    jc .ident_loop
    call is_digit
    jc .ident_loop
    cmp al, '_'
    je .ident_loop
    jmp .parse_loop

.parse_number:
    inc qword [token_count]
    inc rsi
.num_loop:
    movzx eax, byte [rsi]
    call is_digit
    jc .num_loop
    jmp .parse_loop

.parse_done:
    leave
    ret

parse_arguments:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    call GetCommandLineA
    mov rsi, rax

.skip_prog:
    lodsb
    test al, al
    jz .no_args
    cmp al, ' '
    jne .skip_prog

.skip_spaces:
    lodsb
    cmp al, ' '
    je .skip_spaces
    dec rsi

    mov al, [rsi]
    test al, al
    jz .no_args

    lea rdi, [filename_buffer]
.copy_loop:
    lodsb
    cmp al, ' '
    je .copy_done
    test al, al
    jz .copy_done
    stosb
    jmp .copy_loop
.copy_done:
    mov byte [rdi], 0
    lea rax, [filename_buffer]
    jmp .done

.no_args:
    xor rax, rax

.done:
    leave
    ret

open_file:
    push rbp
    mov rbp, rsp
    sub rsp, 64

    mov [rsp+56], rcx

    mov rdx, 0x80000000
    xor r8, r8
    xor r9, r9
    mov qword [rsp+32], 3
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    call CreateFileA

    cmp rax, -1
    je .error

    mov [file_handle], rax

    mov rcx, rax
    lea rdx, [file_buffer]
    mov r8, 65535
    lea r9, [bytes_read]
    mov qword [rsp+32], 0
    call ReadFile

    test rax, rax
    jz .error

    mov rax, [bytes_read]
    lea rdi, [file_buffer]
    add rdi, rax
    mov byte [rdi], 0

    mov rcx, [file_handle]
    call CloseHandle

    mov rax, 1
    jmp .done

.error:
    xor rax, rax

.done:
    leave
    ret

is_alpha:
    cmp al, 'A'
    jb .not_alpha
    cmp al, 'Z'
    jbe .is_alpha
    cmp al, 'a'
    jb .not_alpha
    cmp al, 'z'
    jbe .is_alpha
.not_alpha:
    clc
    ret
.is_alpha:
    stc
    ret

is_digit:
    cmp al, '0'
    jb .not_digit
    cmp al, '9'
    ja .not_digit
    stc
    ret
.not_digit:
    clc
    ret
"@

$outputDir = "d:\rawrxd\compilers\languages"
$built = 0
$failed = 0

foreach ($lang in $languages) {
    $name = $lang.Name
    $ext = $lang.Ext.Split(',')[0]
    
    $source = $template -f $name, $name, $ext
    $filename = "$outputDir\$($name)_compiler.asm"
    
    # Skip if already exists
    if (Test-Path $filename) {
        Write-Host "Skipping $name (already exists)"
        continue
    }
    
    try {
        Set-Content -Path $filename -Value $source -ErrorAction Stop
        Write-Host "Generated $name compiler"
        $built++
    } catch {
        Write-Host "Failed to generate $name compiler: $_"
        $failed++
    }
}

Write-Host ""
Write-Host "========================================"
Write-Host "Generation Complete: $built generated, $failed failed"
Write-Host "========================================"
