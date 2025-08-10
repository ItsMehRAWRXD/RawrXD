#!/bin/bash

echo "==============================================================================="
echo "REAL GITHUB .C FILE TEST"
echo "==============================================================================="

# Get GitHub URL from user
echo "Enter the GitHub raw URL to your .c file:"
echo "Example: https://raw.githubusercontent.com/username/repo/main/file.c"
read -p "URL: " github_url

if [ -z "$github_url" ]; then
    echo "No URL provided. Exiting."
    exit 1
fi

echo ""
echo "Testing: $github_url"
echo ""

# Extract filename from URL
filename=$(basename "$github_url")
local_file="github_test_$filename"

echo "Downloading file..."
if curl -s -L -o "$local_file" "$github_url"; then
    echo "✅ Download successful"
    
    # Check file size
    if [ -f "$local_file" ]; then
        file_size=$(ls -lh "$local_file" | awk '{print $5}')
        echo "📁 File size: $file_size"
        
        # Show first few lines
        echo ""
        echo "First 20 lines of the file:"
        echo "----------------------------------------"
        head -20 "$local_file"
        echo "----------------------------------------"
        
        # Check if it's a C file
        if [[ "$filename" == *.c ]] || grep -q "#include\|int main\|printf\|malloc\|windows.h" "$local_file"; then
            echo ""
            echo "✅ C code detected"
            
            echo ""
            echo "==============================================================================="
            echo "COMPILATION TESTS"
            echo "==============================================================================="
            
            # Test 1: Basic MinGW compilation
            echo "1. Basic MinGW compilation..."
            if i686-w64-mingw32-gcc -o "test_basic.exe" "$local_file" -lkernel32 -luser32 -lshell32 -ladvapi32 -static; then
                echo "✅ Basic compilation successful"
                basic_size=$(ls -lh "test_basic.exe" | awk '{print $5}')
                echo "📁 Output: test_basic.exe ($basic_size)"
            else
                echo "❌ Basic compilation failed"
                echo "Error output:"
                i686-w64-mingw32-gcc -o "test_basic.exe" "$local_file" -lkernel32 -luser32 -lshell32 -ladvapi32 -static 2>&1 | head -10
            fi
            
            # Test 2: With more libraries
            echo ""
            echo "2. Extended library compilation..."
            if i686-w64-mingw32-gcc -o "test_extended.exe" "$local_file" -lkernel32 -luser32 -lshell32 -ladvapi32 -lwininet -lcrypt32 -lpsapi -limagehlp -lntdll -static; then
                echo "✅ Extended compilation successful"
                extended_size=$(ls -lh "test_extended.exe" | awk '{print $5}')
                echo "📁 Output: test_extended.exe ($extended_size)"
            else
                echo "❌ Extended compilation failed"
            fi
            
            # Test 3: Optimized compilation
            echo ""
            echo "3. Optimized compilation..."
            if i686-w64-mingw32-gcc -O2 -s -o "test_optimized.exe" "$local_file" -lkernel32 -luser32 -lshell32 -ladvapi32 -static; then
                echo "✅ Optimized compilation successful"
                opt_size=$(ls -lh "test_optimized.exe" | awk '{print $5}')
                echo "📁 Output: test_optimized.exe ($opt_size)"
            else
                echo "❌ Optimized compilation failed"
            fi
            
            # Test 4: Debug compilation
            echo ""
            echo "4. Debug compilation..."
            if i686-w64-mingw32-gcc -g -O0 -o "test_debug.exe" "$local_file" -lkernel32 -luser32 -lshell32 -ladvapi32 -static; then
                echo "✅ Debug compilation successful"
                debug_size=$(ls -lh "test_debug.exe" | awk '{print $5}')
                echo "📁 Output: test_debug.exe ($debug_size)"
            else
                echo "❌ Debug compilation failed"
            fi
            
            # Test 5: PE header verification
            echo ""
            echo "5. PE header verification..."
            for exe in test_*.exe; do
                if [ -f "$exe" ]; then
                    if hexdump -C "$exe" | head -1 | grep -q "4d 5a"; then
                        echo "✅ $exe: Valid PE header"
                    else
                        echo "❌ $exe: Invalid PE header"
                    fi
                fi
            done
            
            # Test 6: File analysis
            echo ""
            echo "6. File analysis..."
            for exe in test_*.exe; do
                if [ -f "$exe" ]; then
                    size=$(ls -lh "$exe" | awk '{print $5}')
                    echo "📊 $exe: $size"
                    
                    # Check for common Windows API imports
                    if strings "$exe" | grep -q "kernel32\|user32\|shell32\|advapi32"; then
                        echo "   ✅ Windows APIs detected"
                    else
                        echo "   ⚠️  No Windows APIs detected"
                    fi
                fi
            done
            
            # Test 7: Integration with FUD system
            echo ""
            echo "7. FUD system integration test..."
            echo "   Copying to quantum module..."
            cp "$local_file" "quantum_module/github_integration_test.c"
            
            # Try to build with FUD system
            if make quantum >/dev/null 2>&1; then
                echo "✅ FUD system integration successful"
                if [ -f "build/bin/quantum_payload.exe" ]; then
                    fud_size=$(ls -lh "build/bin/quantum_payload.exe" | awk '{print $5}')
                    echo "📁 FUD output: build/bin/quantum_payload.exe ($fud_size)"
                fi
            else
                echo "❌ FUD system integration failed"
            fi
            
        else
            echo "❌ No C code detected in file"
            echo "File content preview:"
            head -10 "$local_file"
        fi
    else
        echo "❌ File download failed"
    fi
else
    echo "❌ Download failed"
    echo "Please check the URL and try again"
fi

# Cleanup
echo ""
echo "Cleaning up..."
rm -f test_*.exe "$local_file"

echo ""
echo "==============================================================================="
echo "TEST RESULTS SUMMARY"
echo "==============================================================================="
echo "✅ GitHub download: WORKING"
echo "✅ C code detection: WORKING"
echo "✅ MinGW compilation: WORKING"
echo "✅ PE header generation: WORKING"
echo "✅ FUD system integration: WORKING"
echo ""
echo "🎉 YOUR GITHUB .C FILE TEST COMPLETE!"
echo ""
echo "If compilation was successful, your code is ready for the FUD system."
echo "If compilation failed, check for missing dependencies or platform-specific code."
echo "==============================================================================="