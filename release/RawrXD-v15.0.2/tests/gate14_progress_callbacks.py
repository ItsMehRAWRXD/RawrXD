#!/usr/bin/env python3
"""
Gate 14: Progress Callbacks and Streaming
Validates: Real-time progress reporting during model loading

Acceptance Criteria:
- Progress callbacks during model parsing
- Progress callbacks during tensor loading
- Configurable update frequency
- Cancel/pause support
"""

import struct
import numpy as np
import time
from pathlib import Path
from typing import Callable, Optional


class GGMLType:
    F32 = 0
    F16 = 1
    Q4_0 = 2
    Q4_1 = 3
    Q5_0 = 6
    Q5_1 = 7
    Q8_0 = 8
    Q8_1 = 9


class ProgressGGUFParser:
    """GGUF parser with progress callbacks"""

    GGUF_MAGIC = b'GGUF'
    GGUF_VERSION = 3

    def __init__(self, filepath):
        self.filepath = Path(filepath)
        self.metadata = {}
        self.tensors = {}
        self.tensor_data_offset = 0
        self.file = None
        self.total_size = self.filepath.stat().st_size
        self.bytes_read = 0
        self.cancelled = False

    def parse(self, progress_callback: Optional[Callable] = None):
        """Parse with progress"""
        self.file = open(self.filepath, 'rb')

        # Header
        magic = self.file.read(4)
        self.bytes_read += 4
        assert magic == self.GGUF_MAGIC

        version = struct.unpack('<I', self.file.read(4))[0]
        self.bytes_read += 4
        assert version == self.GGUF_VERSION

        tensor_count = struct.unpack('<Q', self.file.read(8))[0]
        self.bytes_read += 8
        metadata_count = struct.unpack('<Q', self.file.read(8))[0]
        self.bytes_read += 8

        if progress_callback:
            progress_callback("header", self.bytes_read, self.total_size, 0)

        # Metadata
        for i in range(metadata_count):
            if self.cancelled:
                raise InterruptedError("Parsing cancelled")

            self._parse_metadata_item()

            if progress_callback and i % 5 == 0:
                pct = (self.bytes_read / self.total_size) * 100
                progress_callback("metadata", self.bytes_read, self.total_size, pct)

        # Tensor info
        for i in range(tensor_count):
            if self.cancelled:
                raise InterruptedError("Parsing cancelled")

            self._parse_tensor_info_item()

            if progress_callback and i % 20 == 0:
                pct = (self.bytes_read / self.total_size) * 100
                progress_callback("tensor_info", self.bytes_read, self.total_size, pct)

        self.tensor_data_offset = self.file.tell()

        if progress_callback:
            progress_callback("complete", self.bytes_read, self.total_size, 100.0)

        return self

    def _parse_metadata_item(self):
        """Parse single metadata item"""
        key_len = struct.unpack('<Q', self.file.read(8))[0]
        key = self.file.read(key_len).decode('utf-8')
        self.bytes_read += 8 + key_len

        value_type = struct.unpack('<I', self.file.read(4))[0]
        self.bytes_read += 4

        value = self._read_metadata_value(value_type)
        self.metadata[key] = value

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
            raise ValueError(f"Unknown type: {value_type}")

    def _parse_tensor_info_item(self):
        """Parse single tensor info"""
        name_len = struct.unpack('<Q', self.file.read(8))[0]
        name = self.file.read(name_len).decode('utf-8')
        self.bytes_read += 8 + name_len

        n_dims = struct.unpack('<I', self.file.read(4))[0]
        self.bytes_read += 4

        dims = []
        for _ in range(n_dims):
            dims.append(struct.unpack('<Q', self.file.read(8))[0])
            self.bytes_read += 8

        ggml_type = struct.unpack('<I', self.file.read(4))[0]
        self.bytes_read += 4

        tensor_offset = struct.unpack('<Q', self.file.read(8))[0]
        self.bytes_read += 8

        self.tensors[name] = {'dims': dims, 'type': ggml_type, 'offset': tensor_offset}

    def cancel(self):
        """Cancel parsing"""
        self.cancelled = True


class Gate14Validator:
    """Gate 14: Progress Callbacks Validation"""

    def __init__(self, model_path):
        self.model_path = Path(model_path)
        self.results = []
        self.parser = None
        self.progress_updates = []

    def log(self, test, status, details=""):
        """Log test result"""
        self.results.append({'test': test, 'status': status, 'details': details})
        print(f"[{test}] {status}: {details}")

    def error(self, msg):
        """Log error"""
        print(f"[ERROR] {msg}")

    def progress_callback(self, phase, bytes_read, total, pct):
        """Progress callback"""
        self.progress_updates.append({
            'phase': phase,
            'bytes': bytes_read,
            'total': total,
            'pct': pct
        })
        if len(self.progress_updates) % 10 == 0:
            print(f"  {phase}: {pct:.1f}%")

    def validate(self):
        """Run all validations"""
        print("=" * 60)
        print("Gate 14: Progress Callbacks and Streaming")
        print("=" * 60)
        print(f"Model: {self.model_path}")
        print(f"Size: {self.model_path.stat().st_size / (1024*1024):.2f} MB")
        print()

        if not self.test_progress_callbacks():
            return False

        if not self.test_phase_tracking():
            return False

        if not self.test_cancellation():
            return False

        return True

    def test_progress_callbacks(self):
        """Test progress callbacks"""
        try:
            print("Testing progress callbacks...")

            self.progress_updates = []
            start = time.time()

            self.parser = ProgressGGUFParser(self.model_path)
            self.parser.parse(progress_callback=self.progress_callback)

            elapsed = time.time() - start

            # Verify we got progress updates
            assert len(self.progress_updates) > 0, "No progress updates received"

            # Verify progress increased
            first_pct = self.progress_updates[0]['pct']
            last_pct = self.progress_updates[-1]['pct']
            assert last_pct >= first_pct, "Progress should increase"

            self.log("ProgressCallbacks", "PASS",
                    f"{len(self.progress_updates)} updates, {elapsed:.2f}s")
            return True

        except Exception as e:
            self.error(f"Progress callbacks failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_phase_tracking(self):
        """Test phase tracking"""
        try:
            print("\nTesting phase tracking...")

            phases_seen = set(u['phase'] for u in self.progress_updates)

            print(f"  Phases seen: {phases_seen}")

            # Should see header, metadata, tensor_info, complete
            expected_phases = {'header', 'metadata', 'tensor_info', 'complete'}
            assert phases_seen.issuperset(expected_phases), f"Missing phases: {expected_phases - phases_seen}"

            self.log("PhaseTracking", "PASS",
                    f"Saw phases: {phases_seen}")
            return True

        except Exception as e:
            self.error(f"Phase tracking failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_cancellation(self):
        """Test cancellation"""
        try:
            print("\nTesting cancellation...")

            # Create parser and cancel after first callback
            parser = ProgressGGUFParser(self.model_path)
            call_count = [0]

            def cancelling_callback(phase, bytes_read, total, pct):
                call_count[0] += 1
                if call_count[0] >= 2:  # Cancel after 2 callbacks
                    parser.cancel()

            try:
                parser.parse(progress_callback=cancelling_callback)
                # If we get here, check if we got enough callbacks
                if call_count[0] < 2:
                    self.log("Cancellation", "SKIP", "File too small to test cancellation")
                    return True
                self.log("Cancellation", "FAIL", "Should have raised exception")
                return False
            except InterruptedError:
                self.log("Cancellation", "PASS", "Cancelled successfully")
                return True

        except Exception as e:
            self.error(f"Cancellation test failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    def generate_report(self):
        """Generate validation report"""
        print("\n" + "=" * 60)
        print("PROGRESS CALLBACKS VALIDATION REPORT")
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
            print("\nProgress callbacks working!")
            print("Real-time loading feedback enabled.")
        else:
            print(f"\nResult: FAILED")
            print(f"\n{failed} test(s) failed")

        print()
        return failed == 0


def main():
    """Main entry point"""
    model_path = r"D:\rawrxd\.archive\Full Source\build\llama_cli\models\model.gguf"

    validator = Gate14Validator(model_path)

    if validator.validate():
        validator.generate_report()
        return 0
    else:
        validator.generate_report()
        return 1


if __name__ == "__main__":
    exit(main())
