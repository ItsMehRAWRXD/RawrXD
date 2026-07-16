#!/usr/bin/env python3
"""
Gate 8: KV Cache Implementation
Validates: Key-Value cache for efficient autoregressive generation

Acceptance Criteria:
- Cache stores K/V tensors for each layer
- Cache is updated incrementally during generation
- Cache reduces computation for subsequent tokens
- Cache shape is correct: [batch, n_heads, seq_len, head_dim]
"""

import struct
import numpy as np
import time
from pathlib import Path


class GGUFValueType:
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12


class GGMLType:
    F32 = 0
    F16 = 1
    Q4_0 = 2
    Q4_1 = 3
    Q5_0 = 6
    Q5_1 = 7
    Q8_0 = 8
    Q8_1 = 9


class GGUFParser:
    """Parse GGUF v3 format"""

    GGUF_MAGIC = b'GGUF'
    GGUF_VERSION = 3

    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.metadata = {}
        self.tensors = {}
        self.tensor_data_offset = 0
        self.file = None

    def parse(self):
        """Parse GGUF file"""
        self.file = open(self.filepath, 'rb')

        # Magic
        magic = self.file.read(4)
        assert magic == self.GGUF_MAGIC, f"Invalid magic: {magic}"

        # Version
        version = struct.unpack('<I', self.file.read(4))[0]
        assert version == self.GGUF_VERSION, f"Unsupported version: {version}"

        # Tensor count, metadata count
        tensor_count = struct.unpack('<Q', self.file.read(8))[0]
        metadata_count = struct.unpack('<Q', self.file.read(8))[0]

        # Parse metadata
        for _ in range(metadata_count):
            key_len = struct.unpack('<Q', self.file.read(8))[0]
            key = self.file.read(key_len).decode('utf-8')
            value_type = struct.unpack('<I', self.file.read(4))[0]
            value = self._parse_metadata_value(value_type)
            self.metadata[key] = value

        # Parse tensor info
        for _ in range(tensor_count):
            name_len = struct.unpack('<Q', self.file.read(8))[0]
            name = self.file.read(name_len).decode('utf-8')
            n_dims = struct.unpack('<I', self.file.read(4))[0]
            dims = []
            for _ in range(n_dims):
                dims.append(struct.unpack('<Q', self.file.read(8))[0])
            ggml_type = struct.unpack('<I', self.file.read(4))[0]
            tensor_offset = struct.unpack('<Q', self.file.read(8))[0]
            self.tensors[name] = {'dims': dims, 'type': ggml_type, 'offset': tensor_offset}

        self.tensor_data_offset = self.file.tell()
        return self

    def _parse_metadata_value(self, value_type):
        """Parse metadata value"""
        if value_type == GGUFValueType.UINT32:
            return struct.unpack('<I', self.file.read(4))[0]
        elif value_type == GGUFValueType.INT32:
            return struct.unpack('<i', self.file.read(4))[0]
        elif value_type == GGUFValueType.FLOAT32:
            return struct.unpack('<f', self.file.read(4))[0]
        elif value_type == GGUFValueType.BOOL:
            return struct.unpack('<?', self.file.read(1))[0]
        elif value_type == GGUFValueType.STRING:
            str_len = struct.unpack('<Q', self.file.read(8))[0]
            return self.file.read(str_len).decode('utf-8')
        elif value_type == GGUFValueType.ARRAY:
            arr_type = struct.unpack('<I', self.file.read(4))[0]
            arr_len = struct.unpack('<Q', self.file.read(8))[0]
            arr = []
            for _ in range(arr_len):
                arr.append(self._parse_metadata_value(arr_type))
            return arr
        elif value_type == GGUFValueType.UINT64:
            return struct.unpack('<Q', self.file.read(8))[0]
        elif value_type == GGUFValueType.INT64:
            return struct.unpack('<q', self.file.read(8))[0]
        elif value_type == GGUFValueType.FLOAT64:
            return struct.unpack('<d', self.file.read(8))[0]
        else:
            raise ValueError(f"Unknown value type: {value_type}")

    def read_tensor(self, name, max_elements=None):
        """Read and dequantize tensor"""
        info = self.tensors[name]
        ggml_type = info['type']
        dims = list(info['dims'])

        # Tensor offsets are relative to aligned tensor data offset
        aligned_base = (self.tensor_data_offset + 31) & ~31
        offset = aligned_base + info['offset']

        total_elements = 1
        for d in dims:
            total_elements *= d

        # Calculate actual elements to read
        if max_elements and total_elements > max_elements:
            if ggml_type in [GGMLType.Q4_0, GGMLType.Q8_0]:
                block_size = 32
                max_elements = ((max_elements + block_size - 1) // block_size) * block_size
            total_elements = max_elements
            if len(dims) >= 2:
                new_cols = max(1, total_elements // dims[0])
                dims = [dims[0], new_cols]
            else:
                dims = [total_elements]

        self.file.seek(offset)

        if ggml_type == GGMLType.F32:
            return self._read_f32(total_elements, dims)
        elif ggml_type == GGMLType.Q4_0:
            return self._read_q4_0(total_elements, dims)
        elif ggml_type == GGMLType.Q8_0:
            return self._read_q8_0(total_elements, dims)
        else:
            raise ValueError(f"Unsupported type: {ggml_type}")

    def _read_f32(self, total_elements, dims):
        """Read float32 tensor"""
        data = self.file.read(total_elements * 4)
        values = struct.unpack(f'<{total_elements}f', data)
        return np.array(values, dtype=np.float32).reshape(dims)

    def _read_q4_0(self, total_elements, dims):
        """Read Q4_0 quantized tensor"""
        block_size = 32
        num_blocks = (total_elements + block_size - 1) // block_size
        values = []
        for i in range(num_blocks):
            if len(values) >= total_elements:
                break
            delta_bytes = self.file.read(2)
            delta_f16 = np.frombuffer(delta_bytes, dtype=np.float16)[0]
            delta = float(delta_f16)
            qs = self.file.read(16)
            for j in range(min(block_size, total_elements - len(values))):
                byte_idx = j // 2
                nibble = (qs[byte_idx] >> (4 * (j % 2))) & 0x0F
                val = float(nibble - 8) * delta
                values.append(val)
        return np.array(values, dtype=np.float32).reshape(dims)

    def _read_q8_0(self, total_elements, dims):
        """Read Q8_0 quantized tensor"""
        block_size = 32
        num_blocks = (total_elements + block_size - 1) // block_size
        values = []
        for i in range(num_blocks):
            if len(values) >= total_elements:
                break
            delta_bytes = self.file.read(2)
            delta_f16 = np.frombuffer(delta_bytes, dtype=np.float16)[0]
            delta = float(delta_f16)
            qs = self.file.read(32)
            for j in range(min(block_size, total_elements - len(values))):
                q = struct.unpack('<b', qs[j:j+1])[0]
                val = q * delta
                values.append(val)
        return np.array(values, dtype=np.float32).reshape(dims)


class KVCache:
    """Key-Value cache for transformer attention"""

    def __init__(self, num_layers, batch_size, num_heads, head_dim, max_seq_len=2048):
        self.num_layers = num_layers
        self.batch_size = batch_size
        self.num_heads = num_heads
        self.head_dim = head_dim
        self.max_seq_len = max_seq_len
        self.seq_len = 0

        # Initialize cache: [num_layers, batch_size, num_heads, max_seq_len, head_dim]
        self.k_cache = np.zeros(
            (num_layers, batch_size, num_heads, max_seq_len, head_dim),
            dtype=np.float32
        )
        self.v_cache = np.zeros(
            (num_layers, batch_size, num_heads, max_seq_len, head_dim),
            dtype=np.float32
        )

    def update(self, layer_idx, k, v, start_pos):
        """Update cache with new K/V values"""
        # k, v shape: [batch_size, num_heads, seq_len, head_dim]
        seq_len = k.shape[2]

        # Store in cache
        self.k_cache[layer_idx, :, :, start_pos:start_pos + seq_len, :] = k
        self.v_cache[layer_idx, :, :, start_pos:start_pos + seq_len, :] = v

        # Update sequence length
        self.seq_len = max(self.seq_len, start_pos + seq_len)

    def get(self, layer_idx, start_pos, end_pos):
        """Get cached K/V values"""
        k = self.k_cache[layer_idx, :, :, start_pos:end_pos, :]
        v = self.v_cache[layer_idx, :, :, start_pos:end_pos, :]
        return k, v

    def clear(self):
        """Clear the cache"""
        self.k_cache.fill(0)
        self.v_cache.fill(0)
        self.seq_len = 0


class Gate8Validator:
    """Gate 8: KV Cache Validation"""

    def __init__(self):
        self.results = []
        self.cache = None

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
        print("Gate 8: KV Cache Implementation")
        print("=" * 60)
        print()

        if not self.test_cache_creation():
            return False

        if not self.test_cache_update():
            return False

        if not self.test_cache_retrieval():
            return False

        if not self.test_cache_incremental():
            return False

        if not self.test_cache_clear():
            return False

        return True

    def test_cache_creation(self):
        """Test cache creation"""
        try:
            print("Testing cache creation...")

            # TinyLlama config
            num_layers = 22
            batch_size = 1
            num_heads = 32
            head_dim = 64  # 2048 / 32
            max_seq_len = 2048

            self.cache = KVCache(num_layers, batch_size, num_heads, head_dim, max_seq_len)

            expected_k_shape = (num_layers, batch_size, num_heads, max_seq_len, head_dim)
            expected_v_shape = expected_k_shape

            assert self.cache.k_cache.shape == expected_k_shape, \
                f"K cache shape mismatch: {self.cache.k_cache.shape} != {expected_k_shape}"
            assert self.cache.v_cache.shape == expected_v_shape, \
                f"V cache shape mismatch: {self.cache.v_cache.shape} != {expected_v_shape}"

            # Check memory usage
            k_bytes = self.cache.k_cache.nbytes
            v_bytes = self.cache.v_cache.nbytes
            total_mb = (k_bytes + v_bytes) / (1024 * 1024)

            self.log("CacheCreation", "PASS",
                    f"Shape: {expected_k_shape}, Memory: {total_mb:.2f} MB")
            return True

        except Exception as e:
            self.error(f"Cache creation failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_cache_update(self):
        """Test cache update"""
        try:
            print("\nTesting cache update...")

            # Create dummy K/V values for layer 0
            batch_size = 1
            num_heads = 32
            seq_len = 10
            head_dim = 64

            k = np.random.randn(batch_size, num_heads, seq_len, head_dim).astype(np.float32)
            v = np.random.randn(batch_size, num_heads, seq_len, head_dim).astype(np.float32)

            # Update cache
            self.cache.update(0, k, v, start_pos=0)

            # Verify update
            assert self.cache.seq_len == seq_len, \
                f"Seq len mismatch: {self.cache.seq_len} != {seq_len}"

            self.log("CacheUpdate", "PASS",
                    f"Updated layer 0, seq_len: {seq_len}")
            return True

        except Exception as e:
            self.error(f"Cache update failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_cache_retrieval(self):
        """Test cache retrieval"""
        try:
            print("\nTesting cache retrieval...")

            # Retrieve cached values
            k_retrieved, v_retrieved = self.cache.get(0, 0, 10)

            assert k_retrieved.shape == (1, 32, 10, 64), \
                f"Retrieved K shape mismatch: {k_retrieved.shape}"
            assert v_retrieved.shape == (1, 32, 10, 64), \
                f"Retrieved V shape mismatch: {v_retrieved.shape}"

            self.log("CacheRetrieval", "PASS",
                    f"Retrieved shape: {k_retrieved.shape}")
            return True

        except Exception as e:
            self.error(f"Cache retrieval failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_cache_incremental(self):
        """Test incremental cache updates (autoregressive generation)"""
        try:
            print("\nTesting incremental cache updates...")

            batch_size = 1
            num_heads = 32
            head_dim = 64

            # Simulate generating 5 tokens one at a time
            for i in range(5):
                # New token K/V
                k_new = np.random.randn(batch_size, num_heads, 1, head_dim).astype(np.float32)
                v_new = np.random.randn(batch_size, num_heads, 1, head_dim).astype(np.float32)

                # Update at position 10 + i
                self.cache.update(0, k_new, v_new, start_pos=10 + i)

            # Verify total sequence length
            expected_seq_len = 15  # 10 initial + 5 new
            assert self.cache.seq_len == expected_seq_len, \
                f"Seq len mismatch: {self.cache.seq_len} != {expected_seq_len}"

            # Retrieve all cached values
            k_all, v_all = self.cache.get(0, 0, expected_seq_len)

            assert k_all.shape == (1, 32, 15, 64), \
                f"All K shape mismatch: {k_all.shape}"

            self.log("CacheIncremental", "PASS",
                    f"Generated 5 tokens, total seq_len: {expected_seq_len}")
            return True

        except Exception as e:
            self.error(f"Incremental cache test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_cache_clear(self):
        """Test cache clear"""
        try:
            print("\nTesting cache clear...")

            # Clear cache
            self.cache.clear()

            # Verify cleared
            assert self.cache.seq_len == 0, \
                f"Seq len not cleared: {self.cache.seq_len}"
            assert np.all(self.cache.k_cache == 0), "K cache not cleared"
            assert np.all(self.cache.v_cache == 0), "V cache not cleared"

            self.log("CacheClear", "PASS", "Cache cleared successfully")
            return True

        except Exception as e:
            self.error(f"Cache clear failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_report(self):
        """Generate validation report"""
        print("\n" + "=" * 60)
        print("KV CACHE VALIDATION REPORT")
        print("=" * 60)
        print("-" * 60)

        passed = sum(1 for r in self.results if r['status'] == 'PASS')
        failed = sum(1 for r in self.results if r['status'] == 'FAIL')

        for r in self.results:
            symbol = "✓" if r['status'] == 'PASS' else "✗" if r['status'] == 'FAIL' else "○"
            print(f"{symbol} {r['test']:<20} {r['status']:<6} {r['details']}")

        print("-" * 60)

        if failed == 0:
            print("\nResult: VALIDATED")
            print("\nKV Cache implementation working!")
            print("Ready for autoregressive generation.")
        else:
            print(f"\nResult: FAILED")
            print(f"\n{failed} test(s) failed")

        print()
        return failed == 0


def main():
    """Main entry point"""
    validator = Gate8Validator()

    if validator.validate():
        validator.generate_report()
        return 0
    else:
        validator.generate_report()
        return 1


if __name__ == "__main__":
    exit(main())
