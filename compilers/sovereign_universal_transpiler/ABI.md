# Sovereign Universal Transpiler ABI Contract v0.1

## UIR Module (uir.asm)

### UIRCreateContext
- **Params:** none (uses global static buffers)
- **Returns:** RAX = 1 success

### UIRCreateNode
- **Params:** RCX=opcode, RDX=op0, R8=op1, R9=op2, [RSP+28h]=dst_vreg
- **Returns:** RAX = node ptr or NULL

### UIRGetNode
- **Params:** RCX=context ptr, RDX=index
- **Returns:** RAX = node ptr or NULL

### UIRAddConstant
- **Params:** RCX=string ptr, RDX=string len
- **Returns:** RAX = const index or -1

### UIRAddRelocation
- **Params:** RCX=type, RDX=offset, R8=symbol, R9=addend
- **Returns:** RAX = 0 success, -1 fail

### UIRReset
- **Params:** none
- **Returns:** none

### UIRValidateHeader
- **Params:** RCX=context ptr
- **Returns:** RAX = 0 valid, -1 invalid

### UIRAllocVReg
- **Params:** none
- **Returns:** RAX = vreg number

### UIRGetNodeCount
- **Params:** none
- **Returns:** RAX = node count

### UIRGetConstant
- **Params:** RCX=index
- **Returns:** RAX = const ptr or NULL

## Token Module (token.asm)

### TokenInit
- **Params:** none
- **Returns:** none

### TokenCreate
- **Params:** none
- **Returns:** RAX = token ptr or NULL

### TokenGet
- **Params:** RCX=index
- **Returns:** RAX = token ptr or NULL

### TokenGetCount
- **Params:** none
- **Returns:** RAX = token count

### TokenTypeToString
- **Params:** RCX=token type
- **Returns:** RAX = string ptr

## Lexer Module (lexer.asm)

### LexerInit
- **Params:** RCX=source ptr, RDX=source size
- **Returns:** none

### LexerNext
- **Params:** none
- **Returns:** RAX = token ptr or NULL

### LexerPeek
- **Params:** none
- **Returns:** AL = current char

### LexerAdvance
- **Params:** none
- **Returns:** AL = consumed char

## Frontend Adapters

### PHPCompile / CCompile / PythonCompile
- **Params:** RCX=source buffer, RDX=source size, R8=UIR output buffer
- **Returns:** RAX = node count, or -1 on error

## Optimizer (optimizer.asm)

### OptimizeIR
- **Params:** RCX=UIR buffer ptr, RDX=node count
- **Returns:** RAX = optimized node count

## x64 Emitter (emitter_x64.asm)

### EmitX64
- **Params:** RCX=UIR node array, RDX=node count, R8=text buffer, R9=rdata buffer
- **Returns:** RAX = text bytes emitted

### EmitGetRdataSize
- **Params:** none
- **Returns:** RAX = rdata size

## PE Writer (pe_writer.asm)

### PEWriteFile
- **Params:** RCX=filename (ANSI), RDX=text data, R8=text size, R9=rdata data
- **Returns:** RAX = 1 success, 0 failure

## Compiler (compiler.asm)

### CompileSource
- **Params:** RCX=source buffer, RDX=source size, R8=output filename
- **Returns:** RAX = 0 success, non-zero error

### CompileFile
- **Params:** RCX=input filename (ANSI), RDX=output filename (ANSI)
- **Returns:** RAX = 0 success, non-zero error

### ParseCommandLineAndRun
- **Params:** RCX=command line string
- **Returns:** EAX = 0 success, 1 failure

### mainCRTStartup
- **Params:** none (OS entry point)
- **Returns:** never (calls ExitProcess)
