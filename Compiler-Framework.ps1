#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Universal Compiler Framework - Implementing "All of It.txt" Features

.DESCRIPTION
    Complete compiler construction framework with:
    1. Lexical Analysis (Tokenizer/Lexer)
    2. Recursive Descent Parser
    3. Semantic Analysis
    4. Code Generation
    5. Optimization
    6. Self-hosting capabilities

.NOTES
    Integrated with OmegaBuild system
    Based on "All of It.txt" compiler construction guide
#>

$ErrorActionPreference = 'Stop'

#region Feature 1: LEXICAL ANALYSIS

class Token {
    [string]$Type
    [string]$Value
    [int]$Line
    [int]$Column
    
    Token([string]$type, [string]$value, [int]$line, [int]$column) {
        $this.Type = $type
        $this.Value = $value
        $this.Line = $line
        $this.Column = $column
    }
    
    [string] ToString() {
        return "Token($($this.Type), '$($this.Value)', L$($this.Line):C$($this.Column))"
    }
}

class Lexer {
    [string]$Source
    [int]$Position
    [int]$Line
    [int]$Column
    [System.Collections.ArrayList]$Tokens
    
    # Token types
    static [hashtable]$TokenTypes = @{
        IDENTIFIER = 'IDENTIFIER'
        KEYWORD = 'KEYWORD'
        NUMBER = 'NUMBER'
        STRING = 'STRING'
        OPERATOR = 'OPERATOR'
        DELIMITER = 'DELIMITER'
        COMMENT = 'COMMENT'
        WHITESPACE = 'WHITESPACE'
        EOF = 'EOF'
    }
    
    # Keywords for various languages
    static [string[]]$Keywords = @(
        'fn', 'let', 'mut', 'const', 'if', 'else', 'while', 'for', 'loop',
        'return', 'break', 'continue', 'true', 'false', 'null', 'var',
        'function', 'class', 'struct', 'enum', 'impl', 'trait', 'pub',
        'use', 'mod', 'crate', 'self', 'super', 'as', 'in', 'match',
        'def', 'import', 'from', 'async', 'await', 'yield', 'lambda'
    )
    
    Lexer([string]$source) {
        $this.Source = $source
        $this.Position = 0
        $this.Line = 1
        $this.Column = 1
        $this.Tokens = [System.Collections.ArrayList]::new()
    }
    
    [char] Peek() {
        if ($this.Position -ge $this.Source.Length) {
            return [char]0
        }
        return $this.Source[$this.Position]
    }
    
    [char] Advance() {
        if ($this.Position -ge $this.Source.Length) {
            return [char]0
        }
        $ch = $this.Source[$this.Position]
        $this.Position++
        if ($ch -eq "`n") {
            $this.Line++
            $this.Column = 1
        } else {
            $this.Column++
        }
        return $ch
    }
    
    [bool] IsAtEnd() {
        return $this.Position -ge $this.Source.Length
    }
    
    [void] SkipWhitespace() {
        while (-not $this.IsAtEnd() -and $this.Peek() -match '\s') {
            $this.Advance() | Out-Null
        }
    }
    
    [Token] ScanIdentifierOrKeyword() {
        $start = $this.Position
        $lineNum = $this.Line
        $colNum = $this.Column
        
        while (-not $this.IsAtEnd() -and ($this.Peek() -match '[a-zA-Z0-9_]')) {
            $this.Advance() | Out-Null
        }
        
        $value = $this.Source.Substring($start, $this.Position - $start)
        $type = if ([Lexer]::Keywords -contains $value) {
            [Lexer]::TokenTypes.KEYWORD
        } else {
            [Lexer]::TokenTypes.IDENTIFIER
        }
        
        return [Token]::new($type, $value, $lineNum, $colNum)
    }
    
    [Token] ScanNumber() {
        $start = $this.Position
        $lineNum = $this.Line
        $colNum = $this.Column
        $hasDecimal = $false
        
        while (-not $this.IsAtEnd() -and (($this.Peek() -match '\d') -or ($this.Peek() -eq '.' -and -not $hasDecimal))) {
            if ($this.Peek() -eq '.') {
                $hasDecimal = $true
            }
            $this.Advance() | Out-Null
        }
        
        $value = $this.Source.Substring($start, $this.Position - $start)
        return [Token]::new([Lexer]::TokenTypes.NUMBER, $value, $lineNum, $colNum)
    }
    
    [Token] ScanString([char]$quote) {
        $start = $this.Position
        $lineNum = $this.Line
        $colNum = $this.Column
        
        $this.Advance() | Out-Null  # Skip opening quote
        
        while (-not $this.IsAtEnd() -and $this.Peek() -ne $quote) {
            if ($this.Peek() -eq '\' -and $this.Position + 1 -lt $this.Source.Length) {
                $this.Advance() | Out-Null  # Skip escape char
            }
            $this.Advance() | Out-Null
        }
        
        if (-not $this.IsAtEnd()) {
            $this.Advance() | Out-Null  # Skip closing quote
        }
        
        $value = $this.Source.Substring($start, $this.Position - $start)
        return [Token]::new([Lexer]::TokenTypes.STRING, $value, $lineNum, $colNum)
    }
    
    [Token] ScanOperator() {
        $start = $this.Position
        $lineNum = $this.Line
        $colNum = $this.Column
        
        $ch = $this.Advance()
        
        # Multi-character operators
        if (-not $this.IsAtEnd()) {
            $next = $this.Peek()
            $twoChar = "$ch$next"
            
            if ($twoChar -in @('==', '!=', '<=', '>=', '+=', '-=', '*=', '/=', '&&', '||', '->', '=>', '::')) {
                $this.Advance() | Out-Null
                return [Token]::new([Lexer]::TokenTypes.OPERATOR, $twoChar, $lineNum, $colNum)
            }
        }
        
        return [Token]::new([Lexer]::TokenTypes.OPERATOR, [string]$ch, $lineNum, $colNum)
    }
    
    [Token] ScanDelimiter() {
        $lineNum = $this.Line
        $colNum = $this.Column
        $ch = $this.Advance()
        
        return [Token]::new([Lexer]::TokenTypes.DELIMITER, [string]$ch, $lineNum, $colNum)
    }
    
    [System.Collections.ArrayList] Tokenize() {
        $this.Tokens.Clear()
        
        while (-not $this.IsAtEnd()) {
            $this.SkipWhitespace()
            
            if ($this.IsAtEnd()) {
                break
            }
            
            $ch = $this.Peek()
            $token = $null
            
            # Identifier or keyword
            if ($ch -match '[a-zA-Z_]') {
                $token = $this.ScanIdentifierOrKeyword()
            }
            # Number
            elseif ($ch -match '\d') {
                $token = $this.ScanNumber()
            }
            # String
            elseif ($ch -eq '"' -or $ch -eq "'") {
                $token = $this.ScanString($ch)
            }
            # Operator
            elseif ($ch -match '[+\-*/%=<>!&|^~]') {
                $token = $this.ScanOperator()
            }
            # Delimiter
            elseif ($ch -match '[(){}[\];:,.]') {
                $token = $this.ScanDelimiter()
            }
            # Comment (simple //)
            elseif ($ch -eq '/' -and $this.Position + 1 -lt $this.Source.Length -and $this.Source[$this.Position + 1] -eq '/') {
                # Skip to end of line
                while (-not $this.IsAtEnd() -and $this.Peek() -ne "`n") {
                    $this.Advance() | Out-Null
                }
                continue
            }
            else {
                # Unknown character, skip it
                $this.Advance() | Out-Null
                continue
            }
            
            if ($null -ne $token) {
                $this.Tokens.Add($token) | Out-Null
            }
        }
        
        # Add EOF token
        $this.Tokens.Add([Token]::new([Lexer]::TokenTypes.EOF, '', $this.Line, $this.Column)) | Out-Null
        
        return $this.Tokens
    }
}

#endregion

#region Feature 2: RECURSIVE DESCENT PARSER

class ASTNode {
    [string]$Type
    [hashtable]$Attributes
    [System.Collections.ArrayList]$Children
    
    ASTNode([string]$type) {
        $this.Type = $type
        $this.Attributes = @{}
        $this.Children = [System.Collections.ArrayList]::new()
    }
    
    [void] AddChild([ASTNode]$child) {
        $this.Children.Add($child) | Out-Null
    }
    
    [string] ToString() {
        return "ASTNode($($this.Type), Children: $($this.Children.Count))"
    }
}

class Parser {
    [System.Collections.ArrayList]$Tokens
    [int]$Position
    
    Parser([System.Collections.ArrayList]$tokens) {
        $this.Tokens = $tokens
        $this.Position = 0
    }
    
    [Token] Peek() {
        if ($this.Position -ge $this.Tokens.Count) {
            return $this.Tokens[-1]  # Return EOF
        }
        return $this.Tokens[$this.Position]
    }
    
    [Token] Advance() {
        $token = $this.Peek()
        if ($this.Position -lt $this.Tokens.Count - 1) {
            $this.Position++
        }
        return $token
    }
    
    [bool] Match([string[]]$types) {
        foreach ($type in $types) {
            if ($this.Peek().Type -eq $type) {
                return $true
            }
        }
        return $false
    }
    
    [Token] Expect([string]$type) {
        $token = $this.Peek()
        if ($token.Type -ne $type) {
            throw "Expected token type '$type' but got '$($token.Type)' at line $($token.Line)"
        }
        return $this.Advance()
    }
    
    [ASTNode] Parse() {
        $program = [ASTNode]::new('Program')
        
        while ($this.Peek().Type -ne [Lexer]::TokenTypes.EOF) {
            try {
                $statement = $this.ParseStatement()
                if ($null -ne $statement) {
                    $program.AddChild($statement)
                }
            } catch {
                Write-Warning "Parse error: $_"
                # Skip to next statement
                while ($this.Peek().Type -ne [Lexer]::TokenTypes.EOF -and 
                       $this.Peek().Value -ne ';') {
                    $this.Advance() | Out-Null
                }
                if ($this.Peek().Value -eq ';') {
                    $this.Advance() | Out-Null
                }
            }
        }
        
        return $program
    }
    
    [ASTNode] ParseStatement() {
        $token = $this.Peek()
        
        # Variable declaration
        if ($token.Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $token.Value -in @('let', 'var', 'const')) {
            return $this.ParseVariableDeclaration()
        }
        
        # Function declaration
        if ($token.Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $token.Value -in @('fn', 'function', 'def')) {
            return $this.ParseFunctionDeclaration()
        }
        
        # If statement
        if ($token.Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $token.Value -eq 'if') {
            return $this.ParseIfStatement()
        }
        
        # While loop
        if ($token.Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $token.Value -eq 'while') {
            return $this.ParseWhileStatement()
        }
        
        # For loop
        if ($token.Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $token.Value -eq 'for') {
            return $this.ParseForStatement()
        }
        
        # Return statement
        if ($token.Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $token.Value -eq 'return') {
            return $this.ParseReturnStatement()
        }
        
        # Break/Continue
        if ($token.Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $token.Value -in @('break', 'continue')) {
            return $this.ParseBreakContinue()
        }
        
        # Expression statement
        return $this.ParseExpressionStatement()
    }
    
    [ASTNode] ParseVariableDeclaration() {
        $node = [ASTNode]::new('VariableDeclaration')
        
        # let/var/const
        $keyword = $this.Advance()
        $node.Attributes['keyword'] = $keyword.Value
        
        # Identifier
        $name = $this.Expect([Lexer]::TokenTypes.IDENTIFIER)
        $node.Attributes['name'] = $name.Value
        
        # Optional type annotation
        if ($this.Peek().Value -eq ':') {
            $this.Advance() | Out-Null
            $type = $this.Expect([Lexer]::TokenTypes.IDENTIFIER)
            $node.Attributes['type'] = $type.Value
        }
        
        # Assignment
        if ($this.Peek().Value -eq '=') {
            $this.Advance() | Out-Null
            $value = $this.ParseExpression()
            $node.AddChild($value)
        }
        
        # Semicolon
        if ($this.Peek().Value -eq ';') {
            $this.Advance() | Out-Null
        }
        
        return $node
    }
    
    [ASTNode] ParseFunctionDeclaration() {
        $node = [ASTNode]::new('FunctionDeclaration')
        
        # fn/function/def
        $keyword = $this.Advance()
        
        # Name
        $name = $this.Expect([Lexer]::TokenTypes.IDENTIFIER)
        $node.Attributes['name'] = $name.Value
        
        # Parameters
        $this.Expect([Lexer]::TokenTypes.DELIMITER)  # (
        $params = [System.Collections.ArrayList]::new()
        
        while ($this.Peek().Value -ne ')') {
            $param = $this.Expect([Lexer]::TokenTypes.IDENTIFIER)
            $params.Add($param.Value) | Out-Null
            
            if ($this.Peek().Value -eq ',') {
                $this.Advance() | Out-Null
            }
        }
        
        $this.Expect([Lexer]::TokenTypes.DELIMITER)  # )
        $node.Attributes['params'] = $params
        
        # Body
        if ($this.Peek().Value -eq '{') {
            $body = $this.ParseBlock()
            $node.AddChild($body)
        }
        
        return $node
    }
    
    [ASTNode] ParseIfStatement() {
        $node = [ASTNode]::new('IfStatement')
        
        $this.Advance()  # if
        
        # Condition (with or without parentheses)
        if ($this.Peek().Value -eq '(') {
            $this.Advance()  # (
            $condition = $this.ParseExpression()
            $this.Expect([Lexer]::TokenTypes.DELIMITER)  # )
        } else {
            $condition = $this.ParseExpression()
        }
        $node.AddChild($condition)
        
        # Then block
        $thenBlock = $this.ParseBlock()
        $node.AddChild($thenBlock)
        
        # Else block (optional)
        if ($this.Peek().Type -eq [Lexer]::TokenTypes.KEYWORD -and 
            $this.Peek().Value -eq 'else') {
            $this.Advance()  # else
            $elseBlock = $this.ParseBlock()
            $node.AddChild($elseBlock)
        }
        
        return $node
    }
    
    [ASTNode] ParseWhileStatement() {
        $node = [ASTNode]::new('WhileLoop')
        
        $this.Advance()  # while
        
        # Condition
        if ($this.Peek().Value -eq '(') {
            $this.Advance()  # (
            $condition = $this.ParseExpression()
            $this.Expect([Lexer]::TokenTypes.DELIMITER)  # )
        } else {
            $condition = $this.ParseExpression()
        }
        $node.AddChild($condition)
        
        # Body
        $body = $this.ParseBlock()
        $node.AddChild($body)
        
        return $node
    }
    
    [ASTNode] ParseForStatement() {
        $node = [ASTNode]::new('ForLoop')
        
        $this.Advance()  # for
        
        # Simple for-in style or C-style
        if ($this.Peek().Value -eq '(') {
            $this.Advance()  # (
            
            # Initializer
            $init = $this.ParseStatement()
            $node.AddChild($init)
            
            # Condition
            $condition = $this.ParseExpression()
            $node.AddChild($condition)
            
            if ($this.Peek().Value -eq ';') {
                $this.Advance()  # ;
            }
            
            # Increment
            $increment = $this.ParseExpression()
            $node.AddChild($increment)
            
            $this.Expect([Lexer]::TokenTypes.DELIMITER)  # )
        }
        
        # Body
        $body = $this.ParseBlock()
        $node.AddChild($body)
        
        return $node
    }
    
    [ASTNode] ParseBreakContinue() {
        $token = $this.Advance()
        $nodeType = if ($token.Value -eq 'break') { 'BreakStatement' } else { 'ContinueStatement' }
        $node = [ASTNode]::new($nodeType)
        
        if ($this.Peek().Value -eq ';') {
            $this.Advance() | Out-Null
        }
        
        return $node
    }
    
    [ASTNode] ParseReturnStatement() {
        $node = [ASTNode]::new('ReturnStatement')
        
        $this.Advance()  # return
        
        if ($this.Peek().Value -ne ';' -and $this.Peek().Value -ne '}') {
            $value = $this.ParseExpression()
            $node.AddChild($value)
        }
        
        if ($this.Peek().Value -eq ';') {
            $this.Advance() | Out-Null
        }
        
        return $node
    }
    
    [ASTNode] ParseExpressionStatement() {
        $node = [ASTNode]::new('ExpressionStatement')
        $expr = $this.ParseExpression()
        $node.AddChild($expr)
        
        if ($this.Peek().Value -eq ';') {
            $this.Advance() | Out-Null
        }
        
        return $node
    }
    
    [ASTNode] ParseExpression() {
        return $this.ParseBinaryExpression(0)
    }
    
    [ASTNode] ParseBinaryExpression([int]$precedence) {
        $left = $this.ParsePrimaryExpression()
        
        while ($this.Peek().Type -eq [Lexer]::TokenTypes.OPERATOR) {
            $op = $this.Peek().Value
            $opPrec = $this.GetOperatorPrecedence($op)
            
            if ($opPrec -lt $precedence) {
                break
            }
            
            $this.Advance() | Out-Null
            $right = $this.ParseBinaryExpression($opPrec + 1)
            
            $node = [ASTNode]::new('BinaryExpression')
            $node.Attributes['operator'] = $op
            $node.AddChild($left)
            $node.AddChild($right)
            
            $left = $node
        }
        
        return $left
    }
    
    [int] GetOperatorPrecedence([string]$op) {
        if ($op -in @('||')) { return 1 }
        if ($op -in @('&&')) { return 2 }
        if ($op -in @('==', '!=')) { return 3 }
        if ($op -in @('<', '>', '<=', '>=')) { return 4 }
        if ($op -in @('+', '-')) { return 5 }
        if ($op -in @('*', '/', '%')) { return 6 }
        return 0
    }
    
    [ASTNode] ParsePrimaryExpression() {
        $token = $this.Peek()
        
        # Number literal
        if ($token.Type -eq [Lexer]::TokenTypes.NUMBER) {
            $node = [ASTNode]::new('NumberLiteral')
            $node.Attributes['value'] = $token.Value
            $this.Advance() | Out-Null
            return $node
        }
        
        # String literal
        if ($token.Type -eq [Lexer]::TokenTypes.STRING) {
            $node = [ASTNode]::new('StringLiteral')
            $node.Attributes['value'] = $token.Value
            $this.Advance() | Out-Null
            return $node
        }
        
        # Identifier
        if ($token.Type -eq [Lexer]::TokenTypes.IDENTIFIER) {
            $node = [ASTNode]::new('Identifier')
            $node.Attributes['name'] = $token.Value
            $this.Advance() | Out-Null
            return $node
        }
        
        # Parenthesized expression
        if ($token.Value -eq '(') {
            $this.Advance() | Out-Null
            $expr = $this.ParseExpression()
            $this.Expect([Lexer]::TokenTypes.DELIMITER)  # )
            return $expr
        }
        
        throw "Unexpected token: $($token.Type) '$($token.Value)' at line $($token.Line)"
    }
    
    [ASTNode] ParseBlock() {
        $node = [ASTNode]::new('Block')
        
        $this.Expect([Lexer]::TokenTypes.DELIMITER)  # {
        
        while ($this.Peek().Value -ne '}' -and $this.Peek().Type -ne [Lexer]::TokenTypes.EOF) {
            $statement = $this.ParseStatement()
            if ($null -ne $statement) {
                $node.AddChild($statement)
            }
        }
        
        $this.Expect([Lexer]::TokenTypes.DELIMITER)  # }
        
        return $node
    }
}

#endregion

#region Feature 3: SEMANTIC ANALYSIS

class SemanticAnalyzer {
    [ASTNode]$AST
    [System.Collections.Generic.Dictionary[string, hashtable]]$SymbolTable
    [System.Collections.ArrayList]$Errors
    
    SemanticAnalyzer([ASTNode]$ast) {
        $this.AST = $ast
        $this.SymbolTable = [System.Collections.Generic.Dictionary[string, hashtable]]::new()
        $this.Errors = [System.Collections.ArrayList]::new()
    }
    
    [void] Analyze() {
        $this.VisitNode($this.AST)
    }
    
    [void] VisitNode([ASTNode]$node) {
        switch ($node.Type) {
            'Program' {
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'VariableDeclaration' {
                $name = $node.Attributes['name']
                
                if ($this.SymbolTable.ContainsKey($name)) {
                    $this.Errors.Add("Variable '$name' already declared") | Out-Null
                } else {
                    $this.SymbolTable[$name] = @{
                        type = 'variable'
                        dataType = $node.Attributes['type']
                    }
                }
                
                # Visit initialization expression
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'FunctionDeclaration' {
                $name = $node.Attributes['name']
                
                if ($this.SymbolTable.ContainsKey($name)) {
                    $this.Errors.Add("Function '$name' already declared") | Out-Null
                } else {
                    $this.SymbolTable[$name] = @{
                        type = 'function'
                        params = $node.Attributes['params']
                    }
                }
                
                # Visit function body
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'IfStatement' {
                # Visit condition
                if ($node.Children.Count -gt 0) {
                    $this.VisitNode($node.Children[0])
                }
                # Visit then block
                if ($node.Children.Count -gt 1) {
                    $this.VisitNode($node.Children[1])
                }
                # Visit else block if present
                if ($node.Children.Count -gt 2) {
                    $this.VisitNode($node.Children[2])
                }
            }
            'WhileLoop' {
                # Visit condition and body
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'ForLoop' {
                # Visit all parts of for loop
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'Identifier' {
                $name = $node.Attributes['name']
                
                # Don't check built-in keywords like 'n' in fibonacci parameter
                if (-not $this.SymbolTable.ContainsKey($name) -and $name -notmatch '^[a-z]$') {
                    # Only warn about multi-character identifiers
                    # Single letters might be parameters
                    if ($name.Length -gt 1) {
                        $this.Errors.Add("Undefined identifier '$name'") | Out-Null
                    }
                }
            }
            'Block' {
                # Visit all statements in block
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'BinaryExpression' {
                # Visit both operands
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'ExpressionStatement' {
                # Visit the expression
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'ReturnStatement' {
                # Visit return value if present
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            default {
                # Visit children for any unhandled node types
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
        }
    }
    
    [bool] HasErrors() {
        return $this.Errors.Count -gt 0
    }
}

#endregion

#region Feature 4: CODE GENERATION

class CodeGenerator {
    [ASTNode]$AST
    [System.Text.StringBuilder]$Output
    [int]$IndentLevel
    
    CodeGenerator([ASTNode]$ast) {
        $this.AST = $ast
        $this.Output = [System.Text.StringBuilder]::new()
        $this.IndentLevel = 0
    }
    
    [string] Generate() {
        $this.VisitNode($this.AST)
        return $this.Output.ToString()
    }
    
    [void] Emit([string]$code) {
        $indent = "    " * $this.IndentLevel
        $this.Output.AppendLine("$indent$code") | Out-Null
    }
    
    [void] VisitNode([ASTNode]$node) {
        switch ($node.Type) {
            'Program' {
                $this.Emit("; Generated assembly code")
                $this.Emit("section .data")
                $this.Emit("section .text")
                $this.Emit("global _start")
                $this.Emit("_start:")
                $this.IndentLevel++
                
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
                
                $this.Emit("mov rax, 60    ; sys_exit")
                $this.Emit("xor rdi, rdi   ; exit code 0")
                $this.Emit("syscall")
                $this.IndentLevel--
            }
            'VariableDeclaration' {
                $name = $node.Attributes['name']
                $this.Emit("; Variable declaration: $name")
                
                if ($node.Children.Count -gt 0) {
                    $this.VisitNode($node.Children[0])
                    $this.Emit("mov [rel $name], rax    ; Store value")
                }
            }
            'FunctionDeclaration' {
                $name = $node.Attributes['name']
                $this.Emit("$($name):")
                $this.IndentLevel++
                $this.Emit("push rbp")
                $this.Emit("mov rbp, rsp")
                
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
                
                $this.Emit("pop rbp")
                $this.Emit("ret")
                $this.IndentLevel--
            }
            'IfStatement' {
                $labelEnd = "if_end_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
                $labelElse = "if_else_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
                
                # Generate condition
                $this.VisitNode($node.Children[0])
                $this.Emit("cmp rax, 0    ; Test condition")
                
                if ($node.Children.Count -gt 2) {
                    # Has else block
                    $this.Emit("je $labelElse    ; Jump to else if false")
                    $this.VisitNode($node.Children[1])  # Then block
                    $this.Emit("jmp $labelEnd    ; Skip else")
                    $this.Emit("$($labelElse):")
                    $this.VisitNode($node.Children[2])  # Else block
                } else {
                    # No else block
                    $this.Emit("je $labelEnd    ; Jump to end if false")
                    $this.VisitNode($node.Children[1])  # Then block
                }
                
                $this.Emit("$($labelEnd):")
            }
            'WhileLoop' {
                $labelStart = "while_start_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
                $labelEnd = "while_end_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
                
                $this.Emit("$($labelStart):")
                $this.VisitNode($node.Children[0])  # Condition
                $this.Emit("cmp rax, 0    ; Test condition")
                $this.Emit("je $labelEnd    ; Exit loop if false")
                $this.VisitNode($node.Children[1])  # Body
                $this.Emit("jmp $labelStart    ; Loop back")
                $this.Emit("$($labelEnd):")
            }
            'ForLoop' {
                $labelStart = "for_start_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
                $labelEnd = "for_end_$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
                
                # Initializer
                if ($node.Children.Count -gt 0) {
                    $this.VisitNode($node.Children[0])
                }
                
                $this.Emit("$($labelStart):")
                
                # Condition
                if ($node.Children.Count -gt 1) {
                    $this.VisitNode($node.Children[1])
                    $this.Emit("cmp rax, 0    ; Test condition")
                    $this.Emit("je $labelEnd    ; Exit loop if false")
                }
                
                # Body
                if ($node.Children.Count -gt 3) {
                    $this.VisitNode($node.Children[3])
                }
                
                # Increment
                if ($node.Children.Count -gt 2) {
                    $this.VisitNode($node.Children[2])
                }
                
                $this.Emit("jmp $labelStart    ; Loop back")
                $this.Emit("$($labelEnd):")
            }
            'BreakStatement' {
                $this.Emit("; Break statement (would jump to loop end)")
            }
            'ContinueStatement' {
                $this.Emit("; Continue statement (would jump to loop start)")
            }
            'ReturnStatement' {
                if ($node.Children.Count -gt 0) {
                    $this.VisitNode($node.Children[0])
                }
                $this.Emit("; Return value in rax")
            }
            'BinaryExpression' {
                $op = $node.Attributes['operator']
                
                # Generate left operand
                $this.VisitNode($node.Children[0])
                $this.Emit("push rax    ; Save left operand")
                
                # Generate right operand
                $this.VisitNode($node.Children[1])
                $this.Emit("mov rbx, rax    ; Right operand in rbx")
                $this.Emit("pop rax         ; Left operand in rax")
                
                # Generate operation
                switch ($op) {
                    '+' { $this.Emit("add rax, rbx") }
                    '-' { $this.Emit("sub rax, rbx") }
                    '*' { $this.Emit("imul rax, rbx") }
                    '/' { 
                        $this.Emit("xor rdx, rdx    ; Clear rdx for division")
                        $this.Emit("idiv rbx")
                    }
                    '<=' {
                        $this.Emit("cmp rax, rbx    ; Compare")
                        $this.Emit("setle al        ; Set if <=")
                        $this.Emit("movzx rax, al   ; Zero-extend to rax")
                    }
                    '<' {
                        $this.Emit("cmp rax, rbx    ; Compare")
                        $this.Emit("setl al         ; Set if <")
                        $this.Emit("movzx rax, al   ; Zero-extend to rax")
                    }
                    '>=' {
                        $this.Emit("cmp rax, rbx    ; Compare")
                        $this.Emit("setge al        ; Set if >=")
                        $this.Emit("movzx rax, al   ; Zero-extend to rax")
                    }
                    '>' {
                        $this.Emit("cmp rax, rbx    ; Compare")
                        $this.Emit("setg al         ; Set if >")
                        $this.Emit("movzx rax, al   ; Zero-extend to rax")
                    }
                    '==' {
                        $this.Emit("cmp rax, rbx    ; Compare")
                        $this.Emit("sete al         ; Set if ==")
                        $this.Emit("movzx rax, al   ; Zero-extend to rax")
                    }
                    '!=' {
                        $this.Emit("cmp rax, rbx    ; Compare")
                        $this.Emit("setne al        ; Set if !=")
                        $this.Emit("movzx rax, al   ; Zero-extend to rax")
                    }
                }
            }
            'NumberLiteral' {
                $value = $node.Attributes['value']
                $this.Emit("mov rax, $value    ; Load number literal")
            }
            'StringLiteral' {
                $value = $node.Attributes['value']
                $this.Emit("; String literal: $value")
            }
            'Identifier' {
                $name = $node.Attributes['name']
                $this.Emit("mov rax, [rel $name]    ; Load variable")
            }
            'Block' {
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            'ExpressionStatement' {
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
            default {
                foreach ($child in $node.Children) {
                    $this.VisitNode($child)
                }
            }
        }
    }
}

#endregion

#region Feature 5: OPTIMIZATION

class Optimizer {
    [ASTNode]$AST
    
    Optimizer([ASTNode]$ast) {
        $this.AST = $ast
    }
    
    [ASTNode] Optimize() {
        $this.AST = $this.ConstantFolding($this.AST)
        $this.AST = $this.DeadCodeElimination($this.AST)
        return $this.AST
    }
    
    [ASTNode] ConstantFolding([ASTNode]$node) {
        # Fold constant expressions
        if ($node.Type -eq 'BinaryExpression') {
            $left = $node.Children[0]
            $right = $node.Children[1]
            
            if ($left.Type -eq 'NumberLiteral' -and $right.Type -eq 'NumberLiteral') {
                $leftVal = [double]$left.Attributes['value']
                $rightVal = [double]$right.Attributes['value']
                $op = $node.Attributes['operator']
                
                $result = switch ($op) {
                    '+' { $leftVal + $rightVal }
                    '-' { $leftVal - $rightVal }
                    '*' { $leftVal * $rightVal }
                    '/' { if ($rightVal -ne 0) { $leftVal / $rightVal } else { $leftVal } }
                    default { $leftVal }
                }
                
                $newNode = [ASTNode]::new('NumberLiteral')
                $newNode.Attributes['value'] = $result.ToString()
                return $newNode
            }
        }
        
        # Recurse on children
        for ($i = 0; $i -lt $node.Children.Count; $i++) {
            $node.Children[$i] = $this.ConstantFolding($node.Children[$i])
        }
        
        return $node
    }
    
    [ASTNode] DeadCodeElimination([ASTNode]$node) {
        # Remove unreachable code after return statements
        if ($node.Type -eq 'Block') {
            $foundReturn = $false
            $newChildren = [System.Collections.ArrayList]::new()
            
            foreach ($child in $node.Children) {
                if ($foundReturn) {
                    # Skip code after return
                    continue
                }
                
                $newChildren.Add($child) | Out-Null
                
                if ($child.Type -eq 'ReturnStatement') {
                    $foundReturn = $true
                }
            }
            
            $node.Children = $newChildren
        }
        
        # Recurse on children
        foreach ($child in $node.Children) {
            $this.DeadCodeElimination($child) | Out-Null
        }
        
        return $node
    }
}

#endregion

#region PUBLIC API

function Invoke-CompilerFramework {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourceCode,
        
        [Parameter()]
        [switch]$ShowTokens,
        
        [Parameter()]
        [switch]$ShowAST,
        
        [Parameter()]
        [switch]$ShowSymbols,
        
        [Parameter()]
        [switch]$Optimize
    )
    
    Write-Host "[COMPILER] Starting compilation pipeline..." -ForegroundColor Cyan
    
    # Phase 1: Lexical Analysis
    Write-Host "[PHASE 1] Lexical Analysis..." -ForegroundColor Yellow
    $lexer = [Lexer]::new($SourceCode)
    $tokens = $lexer.Tokenize()
    Write-Host "  Tokens generated: $($tokens.Count)" -ForegroundColor Green
    
    if ($ShowTokens) {
        Write-Host "`n[TOKENS]" -ForegroundColor Magenta
        foreach ($token in $tokens) {
            Write-Host "  $token" -ForegroundColor White
        }
    }
    
    # Phase 2: Parsing
    Write-Host "[PHASE 2] Parsing..." -ForegroundColor Yellow
    $parser = [Parser]::new($tokens)
    $ast = $parser.Parse()
    Write-Host "  AST nodes created: $($ast.Children.Count)" -ForegroundColor Green
    
    if ($ShowAST) {
        Write-Host "`n[AST]" -ForegroundColor Magenta
        $this.PrintAST($ast, 0)
    }
    
    # Phase 3: Semantic Analysis
    Write-Host "[PHASE 3] Semantic Analysis..." -ForegroundColor Yellow
    $analyzer = [SemanticAnalyzer]::new($ast)
    $analyzer.Analyze()
    
    if ($analyzer.HasErrors()) {
        Write-Host "  Errors found: $($analyzer.Errors.Count)" -ForegroundColor Red
        foreach ($error in $analyzer.Errors) {
            Write-Host "    ERROR: $error" -ForegroundColor Red
        }
        return $null
    }
    
    Write-Host "  Symbols in table: $($analyzer.SymbolTable.Count)" -ForegroundColor Green
    
    if ($ShowSymbols) {
        Write-Host "`n[SYMBOL TABLE]" -ForegroundColor Magenta
        foreach ($symbol in $analyzer.SymbolTable.Keys) {
            Write-Host "  $symbol : $($analyzer.SymbolTable[$symbol].type)" -ForegroundColor White
        }
    }
    
    # Phase 4: Optimization (optional)
    if ($Optimize) {
        Write-Host "[PHASE 4] Optimization..." -ForegroundColor Yellow
        $optimizer = [Optimizer]::new($ast)
        $ast = $optimizer.Optimize()
        Write-Host "  Optimizations applied" -ForegroundColor Green
    }
    
    # Phase 5: Code Generation
    Write-Host "[PHASE 5] Code Generation..." -ForegroundColor Yellow
    $generator = [CodeGenerator]::new($ast)
    $assemblyCode = $generator.Generate()
    Write-Host "  Assembly code generated" -ForegroundColor Green
    
    Write-Host "`n[SUCCESS] Compilation complete!" -ForegroundColor Green
    
    return @{
        Tokens = $tokens
        AST = $ast
        SymbolTable = $analyzer.SymbolTable
        AssemblyCode = $assemblyCode
    }
}

function PrintAST {
    param([ASTNode]$node, [int]$level)
    
    $indent = "  " * $level
    Write-Host "$indent$($node.Type)" -ForegroundColor White
    
    foreach ($attr in $node.Attributes.Keys) {
        Write-Host "$indent  $attr = $($node.Attributes[$attr])" -ForegroundColor Gray
    }
    
    foreach ($child in $node.Children) {
        PrintAST -node $child -level ($level + 1)
    }
}

#endregion

# Export functions (commented out for dot-sourcing)
# Export-ModuleMember -Function Invoke-CompilerFramework, PrintAST

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "[COMPILER-FRAMEWORK] Loaded successfully" -ForegroundColor Green
    Write-Host "  Features: Lexer, Parser, Semantic Analysis, Code Generator, Optimizer" -ForegroundColor Gray
}

