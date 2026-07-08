# Generate test files for all 69 languages
$testDir = "d:\rawrxd\compilers\test_corpus"

$testFiles = @{
    "test.rs" = @"
fn main() {
    println!("Hello from Rust");
}
"@
    "test.swift" = @"
import Foundation

print("Hello from Swift")
"@
    "test.kt" = @"
fun main() {
    println("Hello from Kotlin")
}
"@
    "test.rb" = @"
puts "Hello from Ruby"
"@
    "test.php" = @"
<?php
echo "Hello from PHP\n";
?>
"@
    "test.ts" = @"
function hello(): void {
    console.log("Hello from TypeScript");
}

hello();
"@
    "test.pl" = @"
#!/usr/bin/perl
print "Hello from Perl\n";
"@
    "test.lua" = @"
print("Hello from Lua")
"@
    "test.r" = @"
hello <- function() {
    print("Hello from R")
}
hello()
"@
    "test.scala" = @"
object Hello {
    def main(args: Array[String]): Unit = {
        println("Hello from Scala")
    }
}
"@
    "test.groovy" = @"
println "Hello from Groovy"
"@
    "test.dart" = @"
void main() {
    print('Hello from Dart');
}
"@
    "test.jl" = @"
function hello()
    println("Hello from Julia")
end
hello()
"@
    "test.hs" = @"
main = putStrLn "Hello from Haskell"
"@
    "test.clj" = @"
(println "Hello from Clojure")
"@
    "test.erl" = @"
-module(hello).
-export([hello/0]).

hello() ->
    io:format("Hello from Erlang~n").
"@
    "test.ex" = @"
defmodule Hello do
    def hello do
        IO.puts "Hello from Elixir"
    end
end

Hello.hello()
"@
    "test.ml" = @"
let hello () =
    print_endline "Hello from OCaml"

let () = hello ()
"@
    "test.fs" = @"
printfn "Hello from F#"
"@
    "test.m" = @"
#import <stdio.h>

int main() {
    printf("Hello from Objective-C\n");
    return 0;
}
"@
    "test.d" = @"
import std.stdio;

void main() {
    writeln("Hello from D");
}
"@
    "test.nim" = @"
echo "Hello from Nim"
"@
    "test.cr" = @"
puts "Hello from Crystal"
"@
    "test.zig" = @"
const std = @import("std");

pub fn main() !void {
    std.debug.print("Hello from Zig\n", .{});
}
"@
    "test_v.v" = @"
fn main() {
    println('Hello from V')
}
"@
    "test.odin" = @"
package main

import "core:fmt"

main :: proc() {
    fmt.println("Hello from Odin")
}
"@
    "test.f90" = @"
program hello
    print *, "Hello from Fortran"
end program hello
"@
    "test.cob" = @"
       IDENTIFICATION DIVISION.
       PROGRAM-ID. HELLO.
       PROCEDURE DIVISION.
           DISPLAY "Hello from COBOL".
           STOP RUN.
"@
    "test.pas" = @"
program Hello;
begin
    writeln('Hello from Pascal');
end.
"@
    "test.ada" = @"
with Ada.Text_IO;

procedure Hello is
begin
    Ada.Text_IO.Put_Line("Hello from Ada");
end Hello;
"@
    "test.lisp" = @"
(print "Hello from Lisp")
"@
    "test.scm" = @"
(display "Hello from Scheme")
(newline)
"@
    "test.pro" = @"
hello :- write('Hello from Prolog'), nl.
"@
    "test.fth" = @"
: hello ." Hello from Forth " cr ;
hello
"@
    "test.apl" = @"
'Hello from APL'
"@
    "test.st" = @"
Transcript show: 'Hello from Smalltalk'; cr.
"@
    "test.coffee" = @"
console.log "Hello from CoffeeScript"
"@
    "test.elm" = @"
import Html exposing (text)

main =
    text "Hello from Elm"
"@
    "test.purs" = @"
module Main where

import Effect.Console (log)

main = log "Hello from PureScript"
"@
    "test.re" = @"
print_endline("Hello from Reason");
"@
    "test.res" = @"
Js.log("Hello from ReScript")
"@
    "test.gleam" = @"
import gleam/io

pub fn main() {
    io.println("Hello from Gleam")
}
"@
    "test.wren" = @"
System.print("Hello from Wren")
"@
    "test.gravity" = @"
func main() {
    System.print("Hello from Gravity");
}
"@
    "test.sol" = @"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Hello {
    function hello() public pure returns (string memory) {
        return "Hello from Solidity";
    }
}
"@
    "test.vy" = @"
@external
def hello() -> String[100]:
    return "Hello from Vyper"
"@
    "test.move" = @"
module hello::hello {
    public entry fun hello() {
        std::debug::print(&b"Hello from Move");
    }
}
"@
    "test.cairo" = @"
fn main() {
    println!("Hello from Cairo");
}
"@
    "test.nr" = @"
fn main() {
    println("Hello from Noir");
}
"@
    "test.leo" = @"
function main() {
    console.log("Hello from Leo");
}
"@
    "test.sw" = @"
script;

fn main() {
    log("Hello from Sway");
}
"@
    "test.ink" = @"
# Hello from Ink

This is a test file for the Ink compiler.
"@
    "test.wat" = @"
(module
    (func $hello (export "hello")
        (nop)
    )
)
"@
    "test.ll" = @"
define i32 @main() {
    ret i32 0
}
"@
    "test.mlir" = @"
func.func @hello() {
    return
}
"@
    "test_verilog.v" = @"
module hello;
    initial begin
        $display("Hello from Verilog");
    end
endmodule
"@
    "test.vhd" = @"
library IEEE;
use IEEE.STD_LOGIC_1164.ALL;

entity hello is
end hello;

architecture Behavioral of hello is
begin
    process
    begin
        report "Hello from VHDL";
        wait;
    end process;
end Behavioral;
"@
    "test.sv" = @"
module hello;
    initial begin
        $display("Hello from SystemVerilog");
    end
endmodule
"@
}

$created = 0
foreach ($file in $testFiles.GetEnumerator()) {
    $path = Join-Path $testDir $file.Key
    if (-not (Test-Path $path)) {
        Set-Content -Path $path -Value $file.Value
        Write-Host "Created $file.Key"
        $created++
    } else {
        Write-Host "Skipped $file.Key (already exists)"
    }
}

Write-Host ""
Write-Host "Created $created test files"
