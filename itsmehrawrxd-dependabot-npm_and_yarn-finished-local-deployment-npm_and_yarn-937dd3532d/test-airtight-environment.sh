#!/bin/bash

# RawrZ Security Platform - Airtight Environment Test
# Tests all API endpoints and panel functionality

echo "🔒 RawrZ Security Platform - Airtight Environment Test"
echo "=================================================="

BASE_URL="http://localhost:3000"
TEST_RESULTS=()

# Function to test API endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_status=$4
    local description=$5
    
    echo "Testing: $description"
    echo "Endpoint: $method $endpoint"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json "$BASE_URL$endpoint")
    else
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" "$BASE_URL$endpoint")
    fi
    
    http_code="${response: -3}"
    
    if [ "$http_code" = "$expected_status" ]; then
        echo "✅ PASS - HTTP $http_code"
        TEST_RESULTS+=("✅ $description")
    else
        echo "❌ FAIL - Expected HTTP $expected_status, got HTTP $http_code"
        TEST_RESULTS+=("❌ $description")
    fi
    
    echo "Response: $(cat /tmp/response.json | head -c 200)..."
    echo ""
}

# Function to test file upload
test_file_upload() {
    local endpoint=$1
    local description=$2
    
    echo "Testing: $description"
    echo "Endpoint: POST $endpoint"
    
    # Create test file
    echo "Test content for upload" > /tmp/test-upload.txt
    
    response=$(curl -s -w "%{http_code}" -o /tmp/response.json -X POST \
        -F "file=@/tmp/test-upload.txt" "$BASE_URL$endpoint")
    
    http_code="${response: -3}"
    
    if [ "$http_code" = "200" ]; then
        echo "✅ PASS - HTTP $http_code"
        TEST_RESULTS+=("✅ $description")
    else
        echo "❌ FAIL - Expected HTTP 200, got HTTP $http_code"
        TEST_RESULTS+=("❌ $description")
    fi
    
    echo "Response: $(cat /tmp/response.json | head -c 200)..."
    echo ""
    
    # Cleanup
    rm -f /tmp/test-upload.txt
}

echo "🚀 Starting comprehensive API tests..."
echo ""

# Test 1: Health Check
test_endpoint "GET" "/api/health" "" "200" "Health Check"

# Test 2: Engines List
test_endpoint "GET" "/api/engines" "" "200" "Engines List"

# Test 3: Engine Health
test_endpoint "GET" "/api/engines/health" "" "200" "Engine Health"

# Test 4: File Upload
test_file_upload "/api/upload" "File Upload"

# Test 5: File Encryption
test_file_upload "/api/encrypt-file" "File Encryption"

# Test 6: File Hashing
test_file_upload "/api/hash-file" "File Hashing"

# Test 7: Bot Management
test_endpoint "GET" "/api/bots" "" "200" "Bot List"

# Test 8: Bot Registration
test_endpoint "POST" "/api/bots/register" '{"name":"Test Bot","type":"http","endpoint":"http://test.com"}' "200" "Bot Registration"

# Test 9: CVE Analysis
test_endpoint "POST" "/api/cve/analyze" '{"cveId":"CVE-2023-1234","analysisType":"basic"}' "200" "CVE Analysis"

# Test 10: CVE Search
test_endpoint "GET" "/api/cve/search?severity=critical" "" "200" "CVE Search"

# Test 11: Payload Management
test_endpoint "GET" "/api/payloads" "" "200" "Payload List"

# Test 12: Payload Creation
test_endpoint "POST" "/api/payloads/create" '{"name":"Test Payload","type":"generic","target":"windows"}' "200" "Payload Creation"

# Test 13: Stub Generation
test_endpoint "POST" "/api/stubs/generate" '{"type":"exe","payload":"test.bin","options":{}}' "200" "Stub Generation"

# Test 14: Real Encryption
test_endpoint "POST" "/api/real-encryption/encrypt" '{"data":"SGVsbG8gV29ybGQ="}' "200" "Real Encryption"

echo "📊 Test Results Summary:"
echo "========================"

passed=0
failed=0

for result in "${TEST_RESULTS[@]}"; do
    echo "$result"
    if [[ $result == ✅* ]]; then
        ((passed++))
    else
        ((failed++))
    fi
done

echo ""
echo "📈 Final Statistics:"
echo "Passed: $passed"
echo "Failed: $failed"
echo "Total: $((passed + failed))"

if [ $failed -eq 0 ]; then
    echo ""
    echo "🎉 ALL TESTS PASSED! Airtight environment is fully functional."
    exit 0
else
    echo ""
    echo "⚠️  Some tests failed. Check the output above for details."
    exit 1
fi
