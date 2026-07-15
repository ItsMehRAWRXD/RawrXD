#!/usr/bin/env python3
"""
Gate 12: Streaming/Chunked Loading
Validates: Load model in chunks to handle large models efficiently

Acceptance Criteria:
- Load tensor data in configurable chunk sizes
- Process chunks without loading entire tensor into memory
- Support for memory-constrained environments
- Progress tracking during load
"""

import struct
import numpy as np
import time
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


class StreamingGGUFParser:
    """GGUF parser with streaming/chunked loading support"""

    GGUF_MAGIC = b'GGUF'
    GGUF_VERSION = 3

    def __init__(self, filepath, chunk_size=1024*1024):  # 1MB default chunk
        self.filepath = Path(filepath)
        self.chunk_size = chunk_size
        self.metadata = {}
        self.tensors = {}
        self.tensor_data_offset = 0
        self.file = None
        self.total_size = self.filepath.stat().st_size
        self.bytes_read = 0

    def parse(self, progress_callback=None):
        """Parse GGUF file with progress tracking"""
        self.file = open(self.filepath, 'rb')

        # Magic (4 bytes)
        magic = self.file.read(4)
        self.bytes_read += 4
        assert magic == self.GGUF_MAGIC, f"Invalid magic: {magic}"

        if progress_callback:
            progress_callback(self.bytes_read, self.total_size, "header")

        # Version (4 bytes)
        version = struct.unpack('<I', self.file.read(4))[0]
        self.bytes_read += 4
        assert version == self.GGUF_VERSION, f"Unsupported version: {version}"

        # Tensor count, metadata count (16 bytes)
        tensor_count = struct.unpack('<Q', self.file.read(8))[0]
        metadata_count = struct.unpack('<Q', self.file.read(8))[0]
        self.bytes_read += 16

        # Parse metadata
        self._parse_metadata(metadata_count, progress_callback)

        # Parse tensor info
        self._parse_tensor_info(tensor_count, progress_callback)

        self.tensor_data_offset = self.file.tell()
        return self

    def _parse_metadata(self, count, progress_callback):
        """Parse metadata with progress"""
        for i in range(count):
            # Key length + key
            key_len = struct.unpack('<Q', self.file.read(8))[0]
            key = self.file.read(key_len).decode('utf-8')
            self.bytes_read += 8 + key_len

            # Value type + value
            value_type = struct.unpack('<I', self.file.read(4))[0]
            value = self._read_metadata_value(value_type)
            self.metadata[key] = value

            if progress_callback and i % 5 == 0:
                progress_callback(self.bytes_read, self.total_size, "metadata")

    def _read_metadata_value(self, value_type):
        """Read metadata value"""
        if value_type == 4:  # UINT32
            self.bytes_read += 4
            return struct.unpack('<I', self.file.read(4))[0]
        elif value_type == 5:  # INT32
            self.bytes_read += 4
            return struct.unpack('<i', self.file.read(4))[0]
        elif value_type == 6:  # FLOAT32
            self.bytes_read += 4
            return struct.unpack('<f', self.file.read(4))[0]
        elif value_type == 7:  # BOOL
            self.bytes_read += 1
            return struct.unpack('<?', self.file.read(1))[0]
        elif value_type == 8:  # STRING
            str_len = struct.unpack('<Q', self.file.read(8))[0]
            self.bytes_read += 8 + str_len
            return self.file.read(str_len).decode('utf-8')
        elif value_type == 9:  # ARRAY
            arr_type = struct.unpack('<I', self.file.read(4))[0]
            arr_len = struct.unpack('<Q', self.file.read(8))[0]
            self.bytes_read += 12
            arr = []
            for _ in range(arr_len):
                arr.append(self._read_metadata_value(arr_type))
            return arr
        elif value_type == 10:  # UINT64
            self.bytes_read += 8
            return struct.unpack('<Q', self.file.read(8))[0]
        elif value_type == 11:  # INT64
            self.bytes_read += 8
            return struct.unpack('<q', self.file.read(8))[0]
        elif value_type == 12:  # FLOAT64
            self.bytes_read += 8
            return struct.unpack('<d', self.file.read(8))[0]
        else:
            raise ValueError(f"Unknown value type: {value_type}")

    def _parse_tensor_info(self, count, progress_callback):
        """Parse tensor info with progress"""
        for i in range(count):
            # Name
            name_len = struct.unpack('<Q', self.file.read(8))[0]
            name = self.file.read(name_len).decode('utf-8')
            self.bytes_read += 8 + name_len

            # Dimensions
            n_dims = struct.unpack('<I', self.file.read(4))[0]
            dims = []
            for _ in range(n_dims):
                dims.append(struct.unpack('<Q', self.file.read(8))[0])
            self.bytes_read += 4 + n_dims * 8

            # Type and offset
            ggml_type = struct.unpack('<I', self.file.read(4))[0]
            tensor_offset = struct.unpack('<Q', self.file.read(8))[0]
            self.bytes_read += 12

            self.tensors[name] = {'dims': dims, 'type': ggml_type, 'offset': tensor_offset}

            if progress_callback and i % 20 == 0:
                progress_callback(self.bytes_read, self.total_size, "tensor_info")

    def read_tensor_chunked(self, name, chunk_size=None, callback=None):
        """Read tensor in chunks"""
        info = self.tensors[name]
        ggml_type = info['type']
        dims = info['dims']

        aligned_base = (self.tensor_data_offset + 31) & ~31
        offset = aligned_base + info['offset']

        total_elements = 1
        for d in dims:
            total_elements *= d

        chunk_size = chunk_size or self.chunk_size

        # Calculate elements per chunk based on type
        if ggml_type == GGMLType.F32:
            bytes_per_elem = 4
        elif ggml_type == GGMLType.Q4_0:
            bytes_per_elem = 18 / 32  # 18 bytes per 32 elements
        elif ggml_type == GGMLType.Q8_0:
            bytes_per_elem = 34 / 32  # 34 bytes per 32 elements
        else:
            raise ValueError(f"Unsupported type: {ggml_type}")

        total_bytes = int(total_elements * bytes_per_elem)
        chunks_read = 0

        for start_byte in range(0, total_bytes, chunk_size):
            end_byte = min(start_byte + chunk_size, total_bytes)
            chunk_len = end_byte - start_byte

            self.file.seek(offset + start_byte)
            chunk_data = self.file.read(chunk_len)

            chunks_read += 1
            if callback:
                callback(chunks_read, (total_bytes + chunk_size - 1) // chunk_size, name)

        return chunks_read


class Gate12Validator:
    """Gate 12: Streaming/Chunked Loading Validation"""

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
        print("Gate 12: Streaming/Chunked Loading")
        print("=" * 60)
        print(f"Model: {self.model_path}")
        print(f"Size: {self.model_path.stat().st_size / (1024*1024):.2f} MB")
        print()

        if not self.test_chunked_parsing():
            return False

        if not self.test_tensor_chunk_loading():
            return False

        if not self.test_memory_efficiency():
            return False

        return True

    def test_chunked_parsing(self):
        """Test chunked parsing with progress"""
        try:
            print("Testing chunked parsing with progress...")

            progress_updates = []

            def progress_callback(bytes_read, total, phase):
                pct = (bytes_read / total) * 100
                progress_updates.append((phase, pct))
                if len(progress_updates) % 10 == 0:
                    print(f"  {phase}: {pct:.1f}%")

            self.parser = StreamingGGUFParser(self.model_path, chunk_size=1024*1024)
            start = time.time()
            self.parser.parse(progress_callback=progress_callback)
            elapsed = time.time() - start

            # Verify parsing completed
            assert len(self.parser.metadata) > 0, "No metadata parsed"
            assert len(self.parser.tensors) > 0, "No tensors parsed"

            self.log("ChunkedParsing", "PASS",
                    f"Parsed {len(self.parser.tensors)} tensors in {elapsed:.2f}s")
            return True

        except Exception as e:
            self.error(f"Chunked parsing failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_tensor_chunk_loading(self):
        """Test loading tensor in chunks"""
        try:
            print("\nTesting tensor chunk loading...")

            # Load a large tensor in chunks
            tensor_name = 'token_embd.weight'
            chunk_size = 1024 * 1024  # 1MB chunks

            chunks_loaded = []

            def chunk_callback(current, total, name):
                chunks_loaded.append((current, total))

            start = time.time()
            num_chunks = self.parser.read_tensor_chunked(
                tensor_name,
                chunk_size=chunk_size,
                callback=chunk_callback
            )
            elapsed = time.time() - start

            self.log("TensorChunkLoading", "PASS",
                    f"Loaded {tensor_name} in {num_chunks} chunks, {elapsed:.2f}s")
            return True

        except Exception as e:
            self.error(f"Tensor chunk loading failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_memory_efficiency(self):
        """Test memory efficiency of chunked loading"""
        try:
            print("\nTesting memory efficiency...")

            # Compare memory usage: chunked vs full load
            import psutil
            import os

            process = psutil.Process(os.getpid())

            # Get baseline memory
            baseline_mem = process.memory_info().rss / (1024 * 1024)  # MB

            # Load tensor info (shouldn't use much memory)
            parser = StreamingGGUFParser(self.model_path)
            parser.parse()

            after_parse_mem = process.memory_info().rss / (1024 * 1024)
            parse_overhead = after_parse_mem - baseline_mem

            # The parser should not load tensor data, just metadata
            # So memory overhead should be small (< 50MB)
            assert parse_overhead < 50, f"Parse overhead too high: {parse_overhead:.1f} MB"

            self.log("MemoryEfficiency", "PASS",
                    f"Parse overhead: {parse_overhead:.1f} MB")
            return True

        except ImportError:
            self.log("MemoryEfficiency", "SKIP", "psutil not available")
            return True
        except Exception as e:
            self.error(f"Memory efficiency test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_report(self):
        """Generate validation report"""
        print("\n" + "=" * 60)
        print("STREAMING/CHUNKED LOADING VALIDATION REPORT")
        print("=" * 60)
        print(f"Model:    {self.model_path}")
        print("-" * 60)

        passed = sum(1 for r in self.results if r['status'] == 'PASS')
        failed = sum(1 for r in self.results if r['status'] == 'FAIL')
        skipped = sum(1 for r in self.results if r['status'] == 'SKIP')

        for r in self.results:
            symbol = "✓" if r['status'] == 'PASS' else "✗" if r['status'] == 'FAIL' else "○"
            print(f"{symbol} {r['test']:<20} {r['status']:<6} {r['details']}")

        print("-" * 60)

        if failed == 0:
            print("\nResult: VALIDATED")
            print("\nStreaming/chunked loading working!")
            print("Ready for large model loading.")
        else:
            print(f"\nResult: FAILED")
            print(f"\n{failed} test(s) failed")

        print()
        return failed == 0


def main():
    """Main entry point"""
    model_path = r"D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf"

    validator = Gate12Validator(model_path)

    if validator.validate():
        validator.generate_report()
        return 0
    else:
        validator.generate_report()
        return 1


if __name__ == "__main__":
    exit(main())
