#!/bin/bash

# RawrZ Native Compilation Setup Script
# Sets up the native Roslyn-for-native compilation system

echo "RawrZ Native Compilation Setup"
echo "=============================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Build the native compilation container
echo "Building native compilation container..."
docker build -f native-compile.Dockerfile -t rawrz-native-compile .

if [ $? -ne 0 ]; then
    echo "Error: Failed to build native compilation container"
    exit 1
fi

# Stop and remove existing container if it exists
echo "Stopping existing native compilation container..."
docker stop native-build 2>/dev/null || true
docker rm native-build 2>/dev/null || true

# Start the native compilation container
echo "Starting native compilation container..."
docker run -d --name native-build -p 8080:8080 rawrz-native-compile

if [ $? -ne 0 ]; then
    echo "Error: Failed to start native compilation container"
    exit 1
fi

# Wait for container to be ready
echo "Waiting for container to be ready..."
sleep 5

# Test the container
echo "Testing native compilation container..."
docker exec native-build /usr/local/bin/native-compile.sh << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello from RawrZ Native Compilation!\n");
    return 0;
}
EOF

if [ $? -eq 0 ]; then
    echo "✓ Native compilation container is working correctly"
else
    echo "✗ Native compilation container test failed"
    exit 1
fi

# Test cross-compilation
echo "Testing cross-compilation..."
echo "Testing Windows PE compilation..."
docker exec -e TARGET_ARCH=windows -e OPTIMIZATION=release native-build /usr/local/bin/native-compile.sh << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello from Windows!\n");
    return 0;
}
EOF

if [ $? -eq 0 ]; then
    echo "✓ Windows cross-compilation is working"
else
    echo "✗ Windows cross-compilation failed"
fi

echo "Testing Linux ELF compilation..."
docker exec -e TARGET_ARCH=linux -e OPTIMIZATION=release native-build /usr/local/bin/native-compile.sh << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello from Linux!\n");
    return 0;
}
EOF

if [ $? -eq 0 ]; then
    echo "✓ Linux compilation is working"
else
    echo "✗ Linux compilation failed"
fi

echo ""
echo "Native Compilation Setup Complete!"
echo "=================================="
echo "Container: native-build"
echo "Port: 8080"
echo "Status: Running"
echo ""
echo "Usage Examples:"
echo "1. Compile C source to Linux executable:"
echo "   echo '#include <stdio.h>\nint main() { printf(\"Hello!\\n\"); return 0; }' | docker exec -i native-build /usr/local/bin/native-compile.sh > hello"
echo ""
echo "2. Cross-compile to Windows PE:"
echo "   echo '#include <stdio.h>\nint main() { printf(\"Hello!\\n\"); return 0; }' | docker exec -e TARGET_ARCH=windows -i native-build /usr/local/bin/native-compile.sh > hello.exe"
echo ""
echo "3. Use via API:"
echo "   curl -X POST http://localhost:3000/api/native-compile/compile -H 'Content-Type: application/json' -d '{\"source\": \"#include <stdio.h>\\nint main() { printf(\\\"Hello!\\n\\\"); return 0; }\", \"target\": \"linux\"}' --output hello"
echo ""
echo "The native compilation system is now ready for use!"
