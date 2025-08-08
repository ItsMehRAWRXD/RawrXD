#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>

class DataConverter {
public:
    // Convert bytes to hex string
    static std::string bytesToHex(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; i++) {
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }
    
    // Convert bytes to hex string with spaces
    static std::string bytesToHexSpaced(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; i++) {
            if (i > 0) ss << " ";
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }
    
    // Convert hex string to bytes
    static std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        std::string cleanHex = hex;
        
        // Remove spaces and 0x prefix if present
        cleanHex.erase(std::remove_if(cleanHex.begin(), cleanHex.end(), ::isspace), cleanHex.end());
        if (cleanHex.substr(0, 2) == "0x" || cleanHex.substr(0, 2) == "0X") {
            cleanHex = cleanHex.substr(2);
        }
        
        // Ensure even length
        if (cleanHex.length() % 2 != 0) {
            cleanHex = "0" + cleanHex;
        }
        
        for (size_t i = 0; i < cleanHex.length(); i += 2) {
            std::string byteString = cleanHex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        
        return bytes;
    }
    
    // Convert bytes to decimal string (as individual values)
    static std::string bytesToDecimal(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        for (size_t i = 0; i < length; i++) {
            if (i > 0) ss << " ";
            ss << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }
    
    // Convert bytes to decimal string (as one large number)
    static std::string bytesToBigDecimal(const uint8_t* bytes, size_t length) {
        // For large numbers, we'll use string arithmetic
        std::string result = "0";
        std::string base = "1";
        
        for (int i = length - 1; i >= 0; i--) {
            std::string byteValue = std::to_string(bytes[i]);
            result = addStrings(result, multiplyStrings(byteValue, base));
            base = multiplyStrings(base, "256");
        }
        
        return result;
    }
    
    // Convert hex string to decimal
    static std::string hexToDecimal(const std::string& hex) {
        std::vector<uint8_t> bytes = hexToBytes(hex);
        return bytesToBigDecimal(bytes.data(), bytes.size());
    }
    
    // Convert decimal string to hex
    static std::string decimalToHex(const std::string& decimal) {
        std::string hex;
        std::string num = decimal;
        
        if (num == "0") return "00";
        
        while (num != "0") {
            int remainder = 0;
            std::string quotient;
            
            // Divide by 16
            for (char digit : num) {
                int current = remainder * 10 + (digit - '0');
                quotient += std::to_string(current / 16);
                remainder = current % 16;
            }
            
            // Remove leading zeros
            size_t firstNonZero = quotient.find_first_not_of('0');
            if (firstNonZero != std::string::npos) {
                num = quotient.substr(firstNonZero);
            } else {
                num = "0";
            }
            
            // Add hex digit
            hex = "0123456789abcdef"[remainder] + hex;
        }
        
        // Ensure even length
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        
        return hex;
    }
    
    // Convert bytes to base64
    static std::string bytesToBase64(const uint8_t* bytes, size_t length) {
        const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string result;
        int val = 0, valb = -6;
        
        for (size_t i = 0; i < length; i++) {
            val = (val << 8) + bytes[i];
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        
        if (valb > -6) {
            result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        
        while (result.size() % 4) {
            result.push_back('=');
        }
        
        return result;
    }
    
    // Convert bytes to C array format
    static std::string bytesToCArray(const uint8_t* bytes, size_t length, const std::string& varName = "data") {
        std::stringstream ss;
        ss << "const unsigned char " << varName << "[" << length << "] = {\n    ";
        
        for (size_t i = 0; i < length; i++) {
            if (i > 0 && i % 16 == 0) ss << "\n    ";
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(bytes[i]);
            if (i < length - 1) ss << ", ";
        }
        
        ss << "\n};";
        return ss.str();
    }
    
    // Convert bytes to assembly format
    static std::string bytesToASM(const uint8_t* bytes, size_t length, const std::string& label = "data") {
        std::stringstream ss;
        ss << label << ":\n    db ";
        
        for (size_t i = 0; i < length; i++) {
            if (i > 0 && i % 16 == 0) ss << "\n    db ";
            else if (i > 0) ss << ", ";
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(bytes[i]);
        }
        
        return ss.str();
    }
    
    // Convert bytes to Python format
    static std::string bytesToPython(const uint8_t* bytes, size_t length, const std::string& varName = "data") {
        std::stringstream ss;
        ss << varName << " = b'";
        
        for (size_t i = 0; i < length; i++) {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(bytes[i]);
        }
        
        ss << "'";
        return ss.str();
    }
    
    // Convert bytes to escaped string
    static std::string bytesToEscapedString(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        
        for (size_t i = 0; i < length; i++) {
            if (bytes[i] >= 32 && bytes[i] <= 126) {
                // Printable ASCII
                if (bytes[i] == '\\' || bytes[i] == '"') {
                    ss << '\\';
                }
                ss << static_cast<char>(bytes[i]);
            } else {
                // Non-printable - use hex escape
                ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') 
                   << static_cast<int>(bytes[i]);
            }
        }
        
        return ss.str();
    }
    
private:
    // String arithmetic helpers for large numbers
    static std::string addStrings(const std::string& num1, const std::string& num2) {
        std::string result;
        int carry = 0;
        int i = num1.length() - 1;
        int j = num2.length() - 1;
        
        while (i >= 0 || j >= 0 || carry) {
            int sum = carry;
            if (i >= 0) sum += num1[i--] - '0';
            if (j >= 0) sum += num2[j--] - '0';
            carry = sum / 10;
            result = std::to_string(sum % 10) + result;
        }
        
        return result;
    }
    
    static std::string multiplyStrings(const std::string& num1, const std::string& num2) {
        int n1 = num1.size(), n2 = num2.size();
        if (n1 == 0 || n2 == 0) return "0";
        
        std::vector<int> result(n1 + n2, 0);
        
        for (int i = n1 - 1; i >= 0; i--) {
            for (int j = n2 - 1; j >= 0; j--) {
                int mul = (num1[i] - '0') * (num2[j] - '0');
                int p1 = i + j, p2 = i + j + 1;
                int sum = mul + result[p2];
                
                result[p2] = sum % 10;
                result[p1] += sum / 10;
            }
        }
        
        std::string str;
        bool leadingZero = true;
        for (int i = 0; i < result.size(); i++) {
            if (result[i] != 0) leadingZero = false;
            if (!leadingZero) str += std::to_string(result[i]);
        }
        
        return str.empty() ? "0" : str;
    }
};

// Example usage and demonstration
int main() {
    std::cout << "=== Data Converter Utility ===" << std::endl;
    std::cout << "Converts between bytes, hex, and decimal representations\n" << std::endl;
    
    // Example data
    uint8_t testBytes[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
    size_t testLength = sizeof(testBytes);
    
    std::cout << "Original bytes (ASCII): ";
    for (size_t i = 0; i < testLength; i++) {
        if (testBytes[i] >= 32 && testBytes[i] <= 126) {
            std::cout << static_cast<char>(testBytes[i]);
        } else {
            std::cout << ".";
        }
    }
    std::cout << "\n\n";
    
    // Demonstrate conversions
    std::cout << "Hex string: " << DataConverter::bytesToHex(testBytes, testLength) << std::endl;
    std::cout << "Hex spaced: " << DataConverter::bytesToHexSpaced(testBytes, testLength) << std::endl;
    std::cout << "Decimal (individual): " << DataConverter::bytesToDecimal(testBytes, testLength) << std::endl;
    std::cout << "Decimal (big number): " << DataConverter::bytesToBigDecimal(testBytes, testLength) << std::endl;
    std::cout << "Base64: " << DataConverter::bytesToBase64(testBytes, testLength) << std::endl;
    std::cout << "Escaped string: \"" << DataConverter::bytesToEscapedString(testBytes, testLength) << "\"" << std::endl;
    
    std::cout << "\nC Array format:\n" << DataConverter::bytesToCArray(testBytes, testLength) << std::endl;
    std::cout << "\nASM format:\n" << DataConverter::bytesToASM(testBytes, testLength) << std::endl;
    std::cout << "\nPython format:\n" << DataConverter::bytesToPython(testBytes, testLength) << std::endl;
    
    // Test conversions
    std::cout << "\n=== Conversion Tests ===" << std::endl;
    std::string hexTest = "48656c6c6f";
    std::cout << "Hex to decimal: " << hexTest << " -> " << DataConverter::hexToDecimal(hexTest) << std::endl;
    
    std::string decTest = "1234567890";
    std::cout << "Decimal to hex: " << decTest << " -> " << DataConverter::decimalToHex(decTest) << std::endl;
    
    // Round trip test
    std::cout << "\n=== Round Trip Test ===" << std::endl;
    std::string originalHex = DataConverter::bytesToHex(testBytes, testLength);
    std::vector<uint8_t> convertedBytes = DataConverter::hexToBytes(originalHex);
    std::string finalHex = DataConverter::bytesToHex(convertedBytes.data(), convertedBytes.size());
    
    std::cout << "Original hex: " << originalHex << std::endl;
    std::cout << "Final hex: " << finalHex << std::endl;
    std::cout << "Match: " << (originalHex == finalHex ? "YES" : "NO") << std::endl;
    
    return 0;
}