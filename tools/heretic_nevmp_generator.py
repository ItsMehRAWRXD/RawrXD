#!/usr/bin/env python3
"""
Heretic NEVMP Generator - Neural Vector Memory Patch Compiler
Generates .nevmp files from ablation vectors for Sovereign Substrate

Usage:
    python heretic_nevmp_generator.py -i input.bin -o patch.nevmp -e 1 -t 0xDEADBEEF
"""

import argparse
import struct
import sys
import os
import zlib
from pathlib import Path

# NEVMP Format Constants
NEVMP_MAGIC = 0x4E564D50  # 'NVMP'
NEVMP_VERSION = 0x00010000  # v1.0.0.0
NEVMP_HEADER_SIZE = 64


def calculate_crc64_iso(data: bytes) -> int:
    """Calculate CRC64-ISO checksum"""
    # Using zlib.crc64 as base, then transform to ISO variant
    # In production, use hardware-accelerated CRC
    crc = zlib.crc64(data, 0) & 0xFFFFFFFFFFFFFFFF
    return crc


def encode_ablation_vectors(raw_data: bytes) -> bytes:
    """
    Apply Heretic Delta encoding:
    encoded[i] = (raw[i] - raw[i-1]) ^ HERETIC_KEY
    """
    HERETIC_KEY = 0x7A
    encoded = bytearray()
    prev = 0x00
    
    for byte in raw_data:
        delta = (byte - prev) & 0xFF
        mutated = delta ^ HERETIC_KEY
        encoded.append(mutated)
        prev = byte
    
    return bytes(encoded)


def create_nevmp_header(epoch_id: int, vector_count: int, 
                        payload_size: int, checksum: int, 
                        target_addr: int) -> bytes:
    """Create NEVMP v1.0 header (64 bytes)"""
    
    header = struct.pack('<I', NEVMP_MAGIC)           # 0x00: magic
    header += struct.pack('<I', NEVMP_VERSION)        # 0x04: version
    header += struct.pack('<Q', epoch_id)              # 0x08: epoch_id
    header += struct.pack('<Q', vector_count)         # 0x10: vector_count
    header += struct.pack('<Q', payload_size)         # 0x18: payload_size
    header += struct.pack('<Q', checksum)             # 0x20: checksum
    header += struct.pack('<Q', target_addr)          # 0x28: target_addr
    header += bytes(16)                                 # 0x30: padding (zeros)
    
    assert len(header) == NEVMP_HEADER_SIZE, f"Header size mismatch: {len(header)}"
    return header


def generate_nevmp(input_file: str, output_file: str, 
                   epoch_id: int, target_addr: int,
                   apply_delta: bool = True) -> bool:
    """Generate .nevmp file from raw ablation vectors"""
    
    # Read input data
    try:
        with open(input_file, 'rb') as f:
            raw_data = f.read()
    except FileNotFoundError:
        print(f"[-] Error: Input file '{input_file}' not found")
        return False
    except Exception as e:
        print(f"[-] Error reading input: {e}")
        return False
    
    if len(raw_data) == 0:
        print("[-] Error: Input file is empty")
        return False
    
    print(f"[*] Loaded {len(raw_data)} bytes of ablation vectors")
    
    # Apply Heretic Delta encoding if requested
    if apply_delta:
        payload = encode_ablation_vectors(raw_data)
        print(f"[*] Applied Heretic Delta encoding (XOR key: 0x7A)")
    else:
        payload = raw_data
        print(f"[*] Using raw vectors (no delta encoding)")
    
    # Calculate payload metadata
    # Each vector is 8 bytes (double precision)
    vector_count = len(payload) // 8
    if len(payload) % 8 != 0:
        # Pad to 8-byte alignment
        padding_needed = 8 - (len(payload) % 8)
        payload += bytes(padding_needed)
        vector_count = len(payload) // 8
        print(f"[*] Padded payload to {len(payload)} bytes ({vector_count} vectors)")
    
    payload_size = len(payload)
    
    # Calculate checksum
    checksum = calculate_crc64_iso(payload)
    print(f"[*] Calculated CRC64-ISO checksum: 0x{checksum:016X}")
    
    # Create header
    header = create_nevmp_header(
        epoch_id=epoch_id,
        vector_count=vector_count,
        payload_size=payload_size,
        checksum=checksum,
        target_addr=target_addr
    )
    
    # Write output file
    try:
        with open(output_file, 'wb') as f:
            f.write(header)
            f.write(payload)
        
        total_size = NEVMP_HEADER_SIZE + payload_size
        print(f"[+] Successfully generated: {output_file}")
        print(f"    Header: {NEVMP_HEADER_SIZE} bytes")
        print(f"    Payload: {payload_size} bytes ({vector_count} vectors)")
        print(f"    Total: {total_size} bytes")
        print(f"    Epoch: {epoch_id}")
        print(f"    Target: 0x{target_addr:016X}")
        return True
        
    except Exception as e:
        print(f"[-] Error writing output: {e}")
        return False


def validate_nevmp(nevmp_file: str) -> bool:
    """Validate a .nevmp file structure"""
    
    try:
        with open(nevmp_file, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return False
    
    if len(data) < NEVMP_HEADER_SIZE:
        print("[-] Error: File too small for NEVMP header")
        return False
    
    # Parse header
    magic = struct.unpack('<I', data[0:4])[0]
    version = struct.unpack('<I', data[4:8])[0]
    epoch_id = struct.unpack('<Q', data[8:16])[0]
    vector_count = struct.unpack('<Q', data[16:24])[0]
    payload_size = struct.unpack('<Q', data[24:32])[0]
    checksum = struct.unpack('<Q', data[32:40])[0]
    target_addr = struct.unpack('<Q', data[40:48])[0]
    
    print(f"[*] NEVMP Header Validation:")
    print(f"    Magic: 0x{magic:08X} (expected: 0x{NEVMP_MAGIC:08X})")
    print(f"    Version: 0x{version:08X} (expected: 0x{NEVMP_VERSION:08X})")
    print(f"    Epoch ID: {epoch_id}")
    print(f"    Vector Count: {vector_count}")
    print(f"    Payload Size: {payload_size}")
    print(f"    Checksum: 0x{checksum:016X}")
    print(f"    Target Address: 0x{target_addr:016X}")
    
    # Validate magic
    if magic != NEVMP_MAGIC:
        print("[-] Error: Invalid magic number")
        return False
    
    # Validate version
    if version != NEVMP_VERSION:
        print("[-] Error: Version mismatch")
        return False
    
    # Validate payload size
    if payload_size != vector_count * 8:
        print(f"[-] Error: Payload size mismatch (expected {vector_count * 8}, got {payload_size})")
        return False
    
    # Validate file size
    expected_size = NEVMP_HEADER_SIZE + payload_size
    if len(data) != expected_size:
        print(f"[-] Error: File size mismatch (expected {expected_size}, got {len(data)})")
        return False
    
    # Validate checksum
    payload = data[NEVMP_HEADER_SIZE:]
    actual_checksum = calculate_crc64_iso(payload)
    if checksum != actual_checksum:
        print(f"[-] Error: Checksum mismatch (expected 0x{checksum:016X}, got 0x{actual_checksum:016X})")
        return False
    
    print("[+] Validation PASSED - File is valid NEVMP v1.0")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Heretic NEVMP Generator - Neural Vector Memory Patch Compiler'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', aliases=['gen', 'g'],
                                        help='Generate .nevmp file from raw vectors')
    gen_parser.add_argument('-i', '--input', required=True,
                           help='Input binary file containing raw ablation vectors')
    gen_parser.add_argument('-o', '--output', required=True,
                           help='Output .nevmp file path')
    gen_parser.add_argument('-e', '--epoch', type=int, default=1,
                           help='Epoch ID for versioning (default: 1)')
    gen_parser.add_argument('-t', '--target', type=lambda x: int(x, 0), default=0,
                           help='Target memory address (hex or decimal)')
    gen_parser.add_argument('--no-delta', action='store_true',
                           help='Disable Heretic Delta encoding')
    
    # Validate command
    val_parser = subparsers.add_parser('validate', aliases=['val', 'v'],
                                      help='Validate a .nevmp file')
    val_parser.add_argument('file', help='.nevmp file to validate')
    
    # Info command
    info_parser = subparsers.add_parser('info', aliases=['i'],
                                       help='Show NEVMP file information')
    info_parser.add_argument('file', help='.nevmp file to inspect')
    
    args = parser.parse_args()
    
    if args.command in ['generate', 'gen', 'g']:
        success = generate_nevmp(
            args.input,
            args.output,
            args.epoch,
            args.target,
            apply_delta=not args.no_delta
        )
        sys.exit(0 if success else 1)
        
    elif args.command in ['validate', 'val', 'v']:
        success = validate_nevmp(args.file)
        sys.exit(0 if success else 1)
        
    elif args.command == 'info':
        validate_nevmp(args.file)  # Same as validate but with info output
        sys.exit(0)
        
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
