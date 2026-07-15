#!/usr/bin/env python3
"""Debug GGUF parsing"""

import struct

with open(r'D:\test_model.gguf', 'rb') as f:
    # Read header
    magic = f.read(4)
    version = struct.unpack('<I', f.read(4))[0]
    tensor_count = struct.unpack('<Q', f.read(8))[0]
    metadata_count = struct.unpack('<Q', f.read(8))[0]
    print(f'Magic: {magic}, Version: {version}')
    print(f'Tensors: {tensor_count}, Metadata: {metadata_count}')
    print(f'Position after header: {f.tell()}')
    
    # Read first metadata
    key_len = struct.unpack('<Q', f.read(8))[0]
    print(f'Key length: {key_len}')
    key = f.read(key_len)
    print(f'Key bytes: {key}')
    try:
        print(f'Key: {key.decode("utf-8")}')
    except:
        print(f'Key (latin-1): {key.decode("latin-1")}')
    print(f'Position after key: {f.tell()}')
    
    # Read value type
    value_type = struct.unpack('<I', f.read(4))[0]
    print(f'Value type: {value_type}')
    print(f'Position after type: {f.tell()}')
    
    # Read value based on type
    if value_type == 8:  # STRING
        str_len = struct.unpack('<Q', f.read(8))[0]
        print(f'String length: {str_len}')
        value = f.read(str_len)
        print(f'Value: {value.decode("utf-8")}')
    print(f'Position after value: {f.tell()}')
    
    # Read second metadata
    key_len = struct.unpack('<Q', f.read(8))[0]
    print(f'\nSecond key length: {key_len}')
    key = f.read(key_len)
    print(f'Second key: {key}')
    try:
        print(f'Second key decoded: {key.decode("utf-8")}')
    except:
        print(f'Second key (latin-1): {key.decode("latin-1")}')
    print(f'Position after second key: {f.tell()}')
    
    # Read value type
    value_type = struct.unpack('<I', f.read(4))[0]
    print(f'Second value type: {value_type}')
    print(f'Position after second type: {f.tell()}')
    
    # Read value based on type
    if value_type == 8:  # STRING
        str_len = struct.unpack('<Q', f.read(8))[0]
        print(f'Second string length: {str_len}')
        value = f.read(str_len)
        print(f'Second value: {value.decode("utf-8")}')
    print(f'Position after second value: {f.tell()}')
