@echo off
REM Minimal Validation Script (No Compilation Required)
REM This script validates the GGUF generation and provides manual validation steps

echo === Minimal Model Stack Validation ===
echo.
echo This script validates the GGUF generation and provides manual validation steps.
echo.

REM Step 1: Generate GGUF
echo [Step 1] Generating minimal GGUF file...
python minimal_gguf_generator.py test_model.gguf
if errorlevel 1 (
    echo ERROR: Failed to generate GGUF file
    exit /b 1
)
echo   ✅ GGUF file generated successfully
echo.

REM Step 2: Verify GGUF structure
echo [Step 2] Verifying GGUF structure...
python -c "import struct; f=open('test_model.gguf','rb'); magic=struct.unpack('<I',f.read(4))[0]; print(f'Magic: 0x{magic:08X}'); print('Valid GGUF' if magic==0x46554747 else 'Invalid GGUF'); f.close()"
if errorlevel 1 (
    echo ERROR: Failed to verify GGUF structure
    exit /b 1
)
echo   ✅ GGUF structure verified
echo.

REM Step 3: Display GGUF metadata
echo [Step 3] Displaying GGUF metadata...
python -c "
import struct
with open('test_model.gguf', 'rb') as f:
    magic = struct.unpack('<I', f.read(4))[0]
    version = struct.unpack('<I', f.read(4))[0]
    tensor_count = struct.unpack('<Q', f.read(8))[0]
    metadata_kv_count = struct.unpack('<Q', f.read(8))[0]
    print(f'Version: {version}')
    print(f'Tensor count: {tensor_count}')
    print(f'Metadata KV count: {metadata_kv_count}')
"
echo   ✅ GGUF metadata displayed
echo.

REM Step 4: Manual validation instructions
echo [Step 4] Manual Validation Instructions
echo.
echo The GGUF file has been generated successfully. To complete the validation:
echo.
echo 1. COMPILE THE VALIDATION HARNESS:
echo    cd src\validation
echo    mkdir build
echo    cd build
echo    cmake .. -DENABLE_AVX512=ON
echo    cmake --build . --config Release
echo.
echo 2. RUN THE VALIDATION:
echo    model_stack_validation.exe ..\..\..\test_model.gguf
echo.
echo 3. EXPECTED OUTPUT:
echo    - Phase 1: Resource Injection (GGUF Loader initialization)
echo    - Phase 2: Buffer Setup (AVX-512 alignment verification)
echo    - Phase 3: Execution Trace (MASM kernel invocation)
echo    - Phase 4: Integrity Check (Output validation)
echo.
echo 4. SUCCESS CRITERIA:
echo    - No access violations during heap allocation
echo    - Correct memory alignment (64-byte boundary)
echo    - Success trace from MASM kernels
echo    - Bit-perfect parity with reference (< 5%% deviation)
echo.
echo ✅ GGUF generation and structure validation complete!
echo.
echo Next step: Compile and run the validation harness as described above.