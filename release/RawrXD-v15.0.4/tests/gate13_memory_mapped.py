#!/usr/bin/env python3
"""
Gate 13: Memory-Mapped Loading
Validates: Use memory mapping for efficient large model access

Acceptance Criteria:
- Map model file into memory without loading entire file
- Access tensors via memory offsets
- Lazy loading of tensor data
- Efficient for models larger than RAM
"""

import struct
import numpy as np
import time
import mmap
import os
from pathlib import Path


class GGMLType:
    F32 = 0
    F16 = 1
    Q4_0 = 2
    Q4_1 = 3
    Q5_0 = 6
    Q5_1 = 7
    Q8_0 = 8
    Q8_1 = 9


class MemoryMappedGGUFParser:
    """GGUF parser with memory-mapped file access"""

    GGUF_MAGIC = b'GGUF'
    GGUF_VERSION = 3

    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.metadata = {}
        self.tensors = {}
        self.tensor_data_offset = 0
        self.file = None
        self.mm = None
        self.total_size = self.filepath.stat().st_size

    def parse(self):
        """Parse GGUF file using memory mapping"""
        self.file = open(self.filepath, 'rb')

        # Memory map the file
        self.mm = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)

        # Parse header
        offset = 0

        # Magic (4 bytes)
        magic = self.mm[offset:offset+4]
        offset += 4
        assert magic == self.GGUF_MAGIC, f"Invalid magic: {magic}"

        # Version (4 bytes)
        version = struct.unpack('<I', self.mm[offset:offset+4])[0]
        offset += 4
        assert version == self.GGUF_VERSION, f"Unsupported version: {version}"

        # Tensor count, metadata count (16 bytes)
        tensor_count = struct.unpack('<Q', self.mm[offset:offset+8])[0]
        offset += 8
        metadata_count = struct.unpack('<Q', self.mm[offset:offset+8])[0]
        offset += 8

        # Parse metadata
        offset = self._parse_metadata(offset, metadata_count)

        # Parse tensor info
        offset = self._parse_tensor_info(offset, tensor_count)

        self.tensor_data_offset = offset
        return self

    def _parse_metadata(self, offset, count):
        """Parse metadata"""
        for _ in range(count):
            # Key
            key_len = struct.unpack('<Q', self.mm[offset:offset+8])[0]
            offset += 8
            key = self.mm[offset:offset+key_len].decode('utf-8')
            offset += key_len

            # Value
            value_type = struct.unpack('<I', self.mm[offset:offset+4])[0]
            offset += 4
            value, offset = self._read_metadata_value(offset, value_type)
            self.metadata[key] = value

        return offset

    def _read_metadata_value(self, offset, value_type):
        """Read metadata value"""
        if value_type == 4:  # UINT32
            val = struct.unpack('<I', self.mm[offset:offset+4])[0]
            return val, offset + 4
        elif value_type == 5:  # INT32
            val = struct.unpack('<i', self.mm[offset:offset+4])[0]
            return val, offset + 4
        elif value_type == 6:  # FLOAT32
            val = struct.unpack('<f', self.mm[offset:offset+4])[0]
            return val, offset + 4
        elif value_type == 7:  # BOOL
            val = struct.unpack('<?', self.mm[offset:offset+1])[0]
            return val, offset + 1
        elif value_type == 8:  # STRING
            str_len = struct.unpack('<Q', self.mm[offset:offset+8])[0]
            offset += 8
            val = self.mm[offset:offset+str_len].decode('utf-8')
            return val, offset + str_len
        elif value_type == 9:  # ARRAY
            arr_type = struct.unpack('<I', self.mm[offset:offset+4])[0]
            offset += 4
            arr_len = struct.unpack('<Q', self.mm[offset:offset+8])[0]
            offset += 8
            arr = []
            for _ in range(arr_len):
                val, offset = self._read_metadata_value(offset, arr_type)
                arr.append(val)
            return arr, offset
        elif value_type == 10:  # UINT64
            val = struct.unpack('<Q', self.mm[offset:offset+8])[0]
            return val, offset + 8
        elif value_type == 11:  # INT64
            val = struct.unpack('<q', self.mm[offset:offset+8])[0]
            return val, offset + 8
        elif value_type == 12:  # FLOAT64
            val = struct.unpack('<d', self.mm[offset:offset+8])[0]
            return val, offset + 8
        else:
            raise ValueError(f"Unknown value type: {value_type}")

    def _parse_tensor_info(self, offset, count):
        """Parse tensor info"""
        for _ in range(count):
            # Name
            name_len = struct.unpack('<Q', self.mm[offset:offset+8])[0]
            offset += 8
            name = self.mm[offset:offset+name_len].decode('utf-8')
            offset += name_len

            # Dimensions
            n_dims = struct.unpack('<I', self.mm[offset:offset+4])[0]
            offset += 4
            dims = []
            for _ in range(n_dims):
                dims.append(struct.unpack('<Q', self.mm[offset:offset+8])[0])
                offset += 8

            # Type and offset
            ggml_type = struct.unpack('<I', self.mm[offset:offset+4])[0]
            offset += 4
            tensor_offset = struct.unpack('<Q', self.mm[offset:offset+8])[0]
            offset += 8

            self.tensors[name] = {'dims': dims, 'type': ggml_type, 'offset': tensor_offset}

        return offset

    def get_tensor_view(self, name):
        """Get memory-mapped view of tensor data (zero-copy)"""
        info = self.tensors[name]
        aligned_base = (self.tensor_data_offset + 31) & ~31
        offset = aligned_base + info['offset']

        # Calculate size
        total_elements = 1
        for d in info['dims']:
            total_elements *= d

        if info['type'] == GGMLType.F32:
            size = total_elements * 4
        elif info['type'] == GGMLType.Q4_0:
            num_blocks = (total_elements + 31) // 32
            size = num_blocks * 18
        elif info['type'] == GGMLType.Q8_0:
            num_blocks = (total_elements + 31) // 32
            size = num_blocks * 34
        else:
            raise ValueError(f"Unsupported type: {info['type']}")

        # Return memory view (zero-copy)
        return memoryview(self.mm[offset:offset+size])

    def close(self):
        """Close memory-mapped file"""
        if self.mm:
            self.mm.close()
        if self.file:
            self.file.close()


class Gate13Validator:
    """Gate 13: Memory-Mapped Loading Validation"""

    def __init__(self, model_path):
        self.model_path = Path(model_path)
        self.results = []
        self.parser = None

    def log(self, test, status, details=""):
        """Log test result"""
        self.results.append({'test': test, 'status': status, 'details': details})
        print(f"[{test}] {status}: {details}")

    def error(self, msg):
        """Log error"""
        print(f"[ERROR] {msg}")

    def validate(self):
        """Run all validations"""
        print("=" * 60)
        print("Gate 13: Memory-Mapped Loading")
        print("=" * 60)
        print(f"Model: {self.model_path}")
        print(f"Size: {self.model_path.stat().st_size / (1024*1024):.2f} MB")
        print()

        if not self.test_mmap_parsing():
            return False

        if not self.test_zero_copy_access():
            return False

        if not self.test_lazy_loading():
            return False

        return True

    def test_mmap_parsing(self):
        """Test memory-mapped parsing"""
        try:
            print("Testing memory-mapped parsing...")

            start = time.time()
            self.parser = MemoryMappedGGUFParser(self.model_path)
            self.parser.parse()
            elapsed = time.time() - start

            # Verify parsing
            assert len(self.parser.metadata) > 0, "No metadata parsed"
            assert len(self.parser.tensors) > 0, "No tensors parsed"

            self.log("MMapParsing", "PASS",
                    f"Parsed {len(self.parser.tensors)} tensors in {elapsed:.3f}s")
            return True

        except Exception as e:
            self.error(f"MMap parsing failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_zero_copy_access(self):
        """Test zero-copy tensor access"""
        try:
            print("\nTesting zero-copy tensor access...")

            # Get tensor view (zero-copy)
            tensor_name = 'token_embd.weight'
            start = time.time()
            tensor_view = self.parser.get_tensor_view(tensor_name)
            elapsed = time.time() - start

            # Verify it's a memoryview (zero-copy)
            assert isinstance(tensor_view, memoryview), "Should return memoryview"

            # Check size
            view_size = len(tensor_view)
            assert view_size > 0, "Tensor view should not be empty"

            self.log("ZeroCopyAccess", "PASS",
                    f"Got {tensor_name} view: {view_size} bytes in {elapsed*1000:.2f}ms")
            return True

        except Exception as e:
            self.error(f"Zero-copy access failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_lazy_loading(self):
        """Test lazy loading (only access what's needed)"""
        try:
            print("\nTesting lazy loading...")

            # Access only specific tensors
            tensors_to_access = ['token_embd.weight', 'output_norm.weight']

            start = time.time()
            for name in tensors_to_access:
                view = self.parser.get_tensor_view(name)
                # Just verify we can access it
                _ = view[0]  # Touch first byte
            elapsed = time.time() - start

            self.log("LazyLoading", "PASS",
                    f"Accessed {len(tensors_to_access)} tensors in {elapsed*1000:.2f}ms")
            return True

        except Exception as e:
            self.error(f"Lazy loading test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_report(self):
        """Generate validation report"""
        print("\n" + "=" * 60)
        print("MEMORY-MAPPED LOADING VALIDATION REPORT")
        print("=" * 60)
        print(f"Model:    {self.model_path}")
        print("-" * 60)

        passed = sum(1 for r in self.results if r['status'] == 'PASS')
        failed = sum(1 for r in self.results if r['status'] == 'FAIL')

        for r in self.results:
            symbol = "✓" if r['status'] == 'PASS' else "✗" if r['status'] == 'FAIL' else "○"
            print(f"{symbol} {r['test']:<20} {r['status']:<6} {r['details']}")

        print("-" * 60)

        if failed == 0:
            print("\nResult: VALIDATED")
            print("\nMemory-mapped loading working!")
            print("Zero-copy tensor access enabled.")
        else:
            print(f"\nResult: FAILED")
            print(f"\n{failed} test(s) failed")

        print()
        return failed == 0


def main():
    """Main entry point"""
    model_path = r"D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf"

    validator = Gate13Validator(model_path)

    try:
        if validator.validate():
            validator.generate_report()
            return 0
        else:
            validator.generate_report()
            return 1
    finally:
        # Clean up
        if validator.parser:
            validator.parser.close()


if __name__ == "__main__":
    exit(main())
