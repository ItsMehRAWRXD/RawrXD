# RawrZ Security Platform - Checkbox-Based Encryption Features

## Overview

The RawrZ Security Platform now features **checkbox-based encryption options** that eliminate the need for text input when configuring advanced encryption parameters. Users can simply check/uncheck boxes to enable or disable specific features, making the platform more user-friendly and accessible.

## New Checkbox-Based Features

### 🔐 **Keyless Encryption**
**Endpoint:** `POST /api/real-encryption/keyless-encrypt`

**Checkbox Options:**
- ✅ **Use Hardware Entropy** - Generates keys from system information (process ID, memory usage, platform, etc.)
- ❌ **Use Hardware Entropy** - Uses pure random key generation

**How it works:**
- No user-provided keys required
- System entropy includes: timestamp, process ID, memory usage, uptime, platform, architecture
- Creates cryptographically secure keys from system fingerprint
- Perfect for scenarios where key management is not desired

### 💾 **Fileless Encryption**
**Endpoint:** `POST /api/real-encryption/fileless-encrypt`

**Checkbox Options:**
- ✅ **Memory Only** - Operations performed entirely in memory
- ✅ **Obfuscate Memory** - XOR encryption with random data to hide memory patterns
- ✅ **Use Process Memory** - Incorporates process memory fingerprint into encryption

**How it works:**
- All operations performed in memory without writing to disk
- Memory obfuscation prevents analysis of memory dumps
- Process memory fingerprint adds unique system identification
- Sensitive data automatically cleared from memory after use

### 🥷 **Beaconism Stealth Generation**
**Endpoint:** `POST /api/real-encryption/beaconism-stealth`

**Checkbox Options:**
- ✅ **Anti-Analysis** - Enables debugger detection, VM detection, and sandbox evasion
- ❌ **Anti-Analysis** - Disables anti-analysis techniques

**Evasion Techniques (Multi-select):**
- ✅ **Polymorphic** - Generates multiple encryption variants
- ✅ **Metamorphic** - Applies structure and code mutations
- ✅ **Obfuscation** - Advanced control flow and string encryption

**How it works:**
- Combines polymorphic encryption with metamorphic transformation
- Applies advanced obfuscation techniques
- Includes anti-analysis protection when enabled
- Generates stealth metadata for tracking

### 🔄 **Polymorphic Encryption**
**Endpoint:** `POST /api/real-encryption/polymorphic-encrypt`

**Checkbox Options:**
- ✅ **Algorithm Rotation** - Rotates between different encryption algorithms
- ❌ **Algorithm Rotation** - Uses single algorithm for all variants

**Parameters:**
- **Variants Count** - Number of encryption variants to generate (default: 3)

**How it works:**
- Generates multiple encryption variants using different algorithms
- Randomly selects one variant for output
- Each variant uses different keys and IVs
- Provides maximum unpredictability

## Checkbox Value Handling

The platform intelligently handles checkbox values from different sources:

```javascript
const parseCheckbox = (value) => {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
        return value === 'true' || value === 'on' || value === '1';
    }
    return true; // Default to enabled for security features
};
```

**Supported Checkbox Formats:**
- `true` / `false` (boolean)
- `"true"` / `"false"` (string)
- `"on"` / `"off"` (HTML checkbox)
- `"1"` / `"0"` (numeric string)

## API Usage Examples

### Keyless Encryption with Checkboxes
```bash
curl -X POST http://localhost:3000/api/real-encryption/keyless-encrypt \
  -F "file=@test.txt" \
  -F "algorithm=aes-256-gcm" \
  -F "useHardwareEntropy=on"
```

### Fileless Encryption with Checkboxes
```bash
curl -X POST http://localhost:3000/api/real-encryption/fileless-encrypt \
  -F "file=@test.txt" \
  -F "algorithm=aes-256-gcm" \
  -F "memoryOnly=on" \
  -F "obfuscateMemory=on" \
  -F "useProcessMemory=on"
```

### Beaconism Stealth with Checkboxes
```bash
curl -X POST http://localhost:3000/api/real-encryption/beaconism-stealth \
  -F "file=@test.txt" \
  -F "stealthLevel=maximum" \
  -F "evasionTechniques=polymorphic,metamorphic,obfuscation" \
  -F "targetOS=windows" \
  -F "antiAnalysis=on"
```

### Polymorphic Encryption with Checkboxes
```bash
curl -X POST http://localhost:3000/api/real-encryption/polymorphic-encrypt \
  -F "file=@test.txt" \
  -F "variants=5" \
  -F "algorithmRotation=on"
```

## Response Format

All endpoints return consistent JSON responses:

```json
{
  "success": true,
  "data": {
    "filename": "test_file_keyless-encrypted_1758356176610.enc",
    "algorithm": "aes-256-gcm",
    "keyless": true,
    "systemEntropy": {
      "timestamp": 1758356176610,
      "processId": 12345,
      "platform": "win32"
    },
    "originalSize": 1024,
    "encryptedSize": 1088,
    "downloadUrl": "/api/files/download-processed/test_file_keyless-encrypted_1758356176610.enc",
    "message": "File encrypted successfully with keyless encryption"
  },
  "timestamp": "2025-01-20T10:30:00.000Z"
}
```

## File Management

### Processed Files Listing
**Endpoint:** `GET /api/files/list-processed`

Returns all processed files with metadata:
```json
{
  "success": true,
  "files": [
    {
      "name": "test_file_keyless-encrypted_1758356176610.enc",
      "size": 1088,
      "createdDate": "2025-01-20T10:30:00.000Z",
      "modifiedDate": "2025-01-20T10:30:00.000Z",
      "downloadUrl": "/api/files/download-processed/test_file_keyless-encrypted_1758356176610.enc"
    }
  ],
  "count": 1,
  "timestamp": "2025-01-20T10:30:00.000Z"
}
```

### File Download
**Endpoint:** `GET /api/files/download-processed/{filename}`

Downloads processed files directly.

## Security Features

### 🔒 **Keyless Security**
- No key management required
- System entropy provides unique keys
- Hardware-based entropy sources
- Cryptographically secure random generation

### 💾 **Fileless Security**
- Memory-only operations
- No disk traces
- Memory obfuscation
- Process fingerprinting
- Automatic memory cleanup

### 🥷 **Stealth Security**
- Polymorphic encryption variants
- Metamorphic code transformation
- Advanced obfuscation layers
- Anti-analysis protection
- Debugger/VM/Sandbox detection

### 🔄 **Polymorphic Security**
- Multiple algorithm variants
- Random variant selection
- Unpredictable encryption patterns
- Maximum entropy generation

## Testing

Use the provided test script to verify checkbox functionality:

```bash
node test-checkbox-encryption.js
```

This script tests all checkbox-based endpoints and demonstrates proper usage.

## Benefits

1. **User-Friendly** - No complex text input required
2. **Secure Defaults** - All security features enabled by default
3. **Flexible** - Easy to enable/disable specific features
4. **Consistent** - Uniform checkbox handling across all endpoints
5. **Accessible** - Works with any HTML form or API client

## Conclusion

The RawrZ Security Platform now provides **checkbox-based encryption** that makes advanced security features accessible to all users. Simply check the boxes for the features you want, and the platform handles all the complex encryption operations automatically.

---

**Platform:** RawrZ Security Platform  
**Version:** Enhanced with Checkbox-Based Encryption  
**Status:** ✅ READY - All checkbox-based encryption features operational
