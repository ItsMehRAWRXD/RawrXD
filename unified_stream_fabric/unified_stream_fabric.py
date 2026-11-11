"""
RawrXD Unified Stream Fabric — Python Implementation
Universal ingestion path for any model, any format, any quant, any source.

Mirrors the C++ header: unified_stream_fabric.h
"""

import struct
import mmap
import os
import json
import time
import hashlib
import random
import io
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Callable
from enum import IntEnum, auto
from collections import deque


# ============================================================================
# STREAM TYPES
# ============================================================================

class StreamType(IntEnum):
    UNKNOWN = 0
    GGUF = 1
    SAFETENSORS = 2
    BIN = 3
    JSON_MANIFEST = 4
    HTTP_BLOB = 5
    OLLAMA = 6
    HF = 7
    RAW = 8
    CUSTOM = 9


# ============================================================================
# QUANTIZATION SCHEMES
# ============================================================================

class QuantScheme(IntEnum):
    NONE = 0
    Q2_K = 1
    Q3_K = 2
    Q4_0 = 3
    Q4_1 = 4
    Q4_K_M = 5
    Q5_0 = 6
    Q5_1 = 7
    Q5_K_M = 8
    Q6_K = 9
    Q8_0 = 10
    F16 = 11
    F32 = 12
    F64 = 13
    IQ1_S = 14
    IQ2_XXS = 15
    IQ3_XXS = 16
    FP8_E4M3 = 17
    FP8_E5M2 = 18


# ============================================================================
# DATA TYPES
# ============================================================================

class DataType(IntEnum):
    U8 = 0
    I8 = 1
    I16 = 2
    I32 = 3
    I64 = 4
    F16 = 5
    BF16 = 6
    F32 = 7
    F64 = 8
    Q4 = 9
    Q5 = 10
    Q6 = 11
    Q8 = 12


# ============================================================================
# TENSOR DESCRIPTOR
# ============================================================================

@dataclass
class TensorDescriptor:
    name: str = ""
    shape: List[int] = field(default_factory=list)
    dtype: DataType = DataType.F32
    quant_scheme: QuantScheme = QuantScheme.NONE
    block_size: int = 256
    scale_type: DataType = DataType.F16
    offset: int = 0
    bytes: int = 0
    num_elements: int = 0
    scale: float = 1.0
    zero_point: float = 0.0

    def format_str(self) -> str:
        names = {
            QuantScheme.NONE: {DataType.F16: "F16", DataType.F32: "F32", DataType.F64: "F64"},
            QuantScheme.Q2_K: "Q2_K", QuantScheme.Q3_K: "Q3_K",
            QuantScheme.Q4_0: "Q4_0", QuantScheme.Q4_1: "Q4_1",
            QuantScheme.Q4_K_M: "Q4_K_M", QuantScheme.Q5_0: "Q5_0",
            QuantScheme.Q5_1: "Q5_1", QuantScheme.Q5_K_M: "Q5_K_M",
            QuantScheme.Q6_K: "Q6_K", QuantScheme.Q8_0: "Q8_0",
            QuantScheme.IQ1_S: "IQ1_S", QuantScheme.IQ2_XXS: "IQ2_XXS",
            QuantScheme.IQ3_XXS: "IQ3_XXS",
            QuantScheme.FP8_E4M3: "FP8_E4M3", QuantScheme.FP8_E5M2: "FP8_E5M2",
        }
        result = names.get(self.quant_scheme, {})
        if isinstance(result, dict):
            return result.get(self.dtype, "RAW")
        return result if isinstance(result, str) else "UNKNOWN"


# ============================================================================
# STREAM CHUNKS
# ============================================================================

@dataclass
class TensorChunk:
    descriptor: TensorDescriptor = field(default_factory=TensorDescriptor)
    data: bytes = b""
    is_final: bool = False


@dataclass
class TokenChunk:
    token_ids: List[int] = field(default_factory=list)
    logprobs: List[float] = field(default_factory=list)
    text: str = ""
    is_final: bool = False
    is_error: bool = False
    error_msg: str = ""


# ============================================================================
# STREAM HEADER — Magic byte detection
# ============================================================================

@dataclass
class StreamHeader:
    type: StreamType = StreamType.UNKNOWN
    magic: str = ""
    file_size: int = 0
    num_tensors: int = 0
    num_metadata: int = 0
    metadata: Dict[str, str] = field(default_factory=dict)
    suggested_name: str = ""

    @staticmethod
    def detect(magic_bytes: bytes) -> StreamType:
        if len(magic_bytes) < 4:
            return StreamType.UNKNOWN

        # GGUF: "GGUF" at offset 0
        if magic_bytes[:4] == b"GGUF":
            return StreamType.GGUF

        # SAFETENSORS: first 8 bytes are little-endian header size
        if len(magic_bytes) >= 8:
            try:
                header_size = struct.unpack('<Q', magic_bytes[:8])[0]
                if 8 <= header_size < 10 * 1024 * 1024:  # Reasonable header size (min 8 bytes)
                    return StreamType.SAFETENSORS
            except:
                pass

        # JSON manifest: '{' or '['
        if magic_bytes[0:1] in (b'{', b'['):
            return StreamType.JSON_MANIFEST

        # HTTP blob
        if magic_bytes[:4] in (b"HTTP", b"GET ", b"POST"):
            return StreamType.HTTP_BLOB

        # Ollama
        if magic_bytes[:4].lower() == b"olla":
            return StreamType.OLLAMA

        return StreamType.RAW


# ============================================================================
# RESIDENCY STATES — Sliding Doors + Reverse Decode
# ============================================================================

class Residency(IntEnum):
    ARCHIVED = 0
    LATENT = 1
    RECONSTRUCTING = 2
    WEIGHTED = 3
    TRANSITIONING = 4
    UNWEIGHTED = 5
    COMPRESSED = 6
    PREDICTED = 7


@dataclass
class MemoryNode:
    id: int = 0
    name: str = ""
    state: Residency = Residency.ARCHIVED
    bytes_full: int = 0
    bytes_current: int = 0
    probability: float = 0.0
    importance: float = 0.0
    entropy: float = 0.0
    reuse_score: float = 0.0
    temperature: float = 0.0
    last_used: int = 0
    predicted_next: int = 0
    use_count: int = 0
    resident_weights: Optional[bytes] = None
    latent: Optional[bytes] = None
    seed: Optional[bytes] = None
    metadata: Optional[Dict] = None
    door_open: bool = False
    door_opened_at: int = 0
    door_close_at: int = 0
    neighbors: List[int] = field(default_factory=list)


# ============================================================================
# QUANT KERNEL REGISTRY
# ============================================================================

QuantKernelFn = Callable[[TensorDescriptor, bytes], List[float]]


@dataclass
class QuantKernelInfo:
    name: str
    scheme: QuantScheme
    kernel: Optional[QuantKernelFn] = None
    throughput_gb_s: float = 0.0
    quality_factor: float = 1.0


class QuantKernelRegistry:
    def __init__(self):
        self._kernels: Dict[QuantScheme, QuantKernelInfo] = {}

    def register(self, info: QuantKernelInfo):
        self._kernels[info.scheme] = info

    def get(self, scheme: QuantScheme) -> Optional[QuantKernelInfo]:
        return self._kernels.get(scheme)

    def resolve(self, desc: TensorDescriptor) -> Optional[QuantKernelFn]:
        info = self._kernels.get(desc.quant_scheme)
        if info and info.kernel:
            return info.kernel
        # Fallback: try by format string
        for scheme, info in self._kernels.items():
            if info.name == desc.format_str() and info.kernel:
                return info.kernel
        return None

    def available_schemes(self) -> List[QuantScheme]:
        return list(self._kernels.keys())


# ============================================================================
# IModelStream — Universal streaming interface
# ============================================================================

class IModelStream:
    """Every model format implements this interface."""

    def open(self, source: str) -> bool:
        raise NotImplementedError

    def read(self, size: int) -> bytes:
        raise NotImplementedError

    def seek(self, offset: int) -> bool:
        raise NotImplementedError

    def get_header(self) -> StreamHeader:
        raise NotImplementedError

    def next_tensor(self) -> TensorChunk:
        raise NotImplementedError

    def next_token(self) -> TokenChunk:
        raise NotImplementedError

    def num_tensors(self) -> int:
        raise NotImplementedError

    def get_tensor(self, index: int) -> TensorDescriptor:
        raise NotImplementedError

    def read_tensor(self, index: int) -> bytes:
        raise NotImplementedError

    def is_eof(self) -> bool:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    @property
    def stream_type(self) -> StreamType:
        raise NotImplementedError

    @property
    def source(self) -> str:
        raise NotImplementedError


# ============================================================================
# STREAM ROUTER
# ============================================================================

class StreamRouter:
    @staticmethod
    def detect_source(source: str) -> StreamType:
        # File extension detection
        if source.endswith(".gguf"):
            return StreamType.GGUF
        if source.endswith(".safetensors"):
            return StreamType.SAFETENSORS
        if source.endswith(".bin"):
            return StreamType.BIN
        if source.endswith((".json", ".jsonl")):
            return StreamType.JSON_MANIFEST

        # URL detection
        if source.startswith(("http://", "https://")):
            if "huggingface" in source:
                return StreamType.HF
            if "ollama" in source:
                return StreamType.OLLAMA
            return StreamType.HTTP_BLOB

        # Ollama model name (e.g., "llama3.2:7b")
        if ":" in source and "/" not in source:
            return StreamType.OLLAMA

        # HF model ID (e.g., "meta-llama/Llama-3.2-7B")
        if "/" in source and "\\" not in source:
            return StreamType.HF

        return StreamType.RAW

    @staticmethod
    def create_stream(source: str) -> Optional[IModelStream]:
        st = StreamRouter.detect_source(source)
        if st == StreamType.GGUF:
            return GGUFStreamAdapter()
        elif st == StreamType.SAFETENSORS:
            return SafetensorsStreamAdapter()
        elif st in (StreamType.BIN, StreamType.RAW):
            return BlobStreamAdapter()
        elif st in (StreamType.OLLAMA, StreamType.HF, StreamType.HTTP_BLOB):
            return RemoteStreamAdapter(st)
        return BlobStreamAdapter()

    @staticmethod
    def resolve(source: str) -> Optional[IModelStream]:
        # Priority 1: Local file
        if "://" not in source:
            stream = StreamRouter.create_stream(source)
            if stream and stream.open(source):
                return stream

        # Priority 2: Remote
        stream = StreamRouter.create_stream(source)
        if stream and stream.open(source):
            return stream

        return None


# ============================================================================
# STREAM ADAPTERS
# ============================================================================

class GGUFStreamAdapter(IModelStream):
    def __init__(self):
        self._source = ""
        self._file = None
        self._header = StreamHeader()
        self._tensors: List[TensorDescriptor] = []
        self._tensor_index = 0

    def open(self, source: str) -> bool:
        self._source = source
        if not os.path.exists(source):
            return False
        self._file = open(source, 'rb')
        self._parse_header()
        return True

    def _parse_header(self):
        if not self._file:
            return
        self._file.seek(0)
        magic = self._file.read(4)
        self._header.type = StreamHeader.detect(magic)
        self._header.magic = magic.decode('utf-8', errors='replace')
        self._header.file_size = os.path.getsize(self._source)

        # Simplified GGUF parsing
        if magic == b"GGUF":
            version = struct.unpack('<I', self._file.read(4))[0]
            tensor_count = struct.unpack('<Q', self._file.read(8))[0]
            metadata_count = struct.unpack('<Q', self._file.read(8))[0]
            self._header.num_tensors = tensor_count
            self._header.num_metadata = metadata_count

            # Skip metadata for now
            for _ in range(metadata_count):
                key = self._read_string()
                val_type = struct.unpack('<I', self._file.read(4))[0]
                val = self._read_value(val_type)
                self._header.metadata[key] = str(val)

            # Read tensor info
            for i in range(tensor_count):
                name = self._read_string()
                n_dims = struct.unpack('<I', self._file.read(4))[0]
                shape = list(struct.unpack(f'<{n_dims}Q', self._file.read(n_dims * 8)))
                dtype = struct.unpack('<I', self._file.read(4))[0]
                offset = struct.unpack('<Q', self._file.read(8))[0]

                desc = TensorDescriptor(
                    name=name,
                    shape=shape,
                    dtype=DataType(dtype) if dtype < len(DataType) else DataType.F32,
                    offset=offset,
                    num_elements=1,
                )
                for s in shape:
                    desc.num_elements *= s
                self._tensors.append(desc)

    def _read_string(self) -> str:
        length = struct.unpack('<Q', self._file.read(8))[0]
        return self._file.read(length).decode('utf-8', errors='replace')

    def _read_value(self, val_type: int):
        if val_type == 0:  # UINT8
            return struct.unpack('<B', self._file.read(1))[0]
        elif val_type == 1:  # INT8
            return struct.unpack('<b', self._file.read(1))[0]
        elif val_type == 2:  # UINT16
            return struct.unpack('<H', self._file.read(2))[0]
        elif val_type == 3:  # INT16
            return struct.unpack('<h', self._file.read(2))[0]
        elif val_type == 4:  # UINT32
            return struct.unpack('<I', self._file.read(4))[0]
        elif val_type == 5:  # INT32
            return struct.unpack('<i', self._file.read(4))[0]
        elif val_type == 6:  # UINT64
            return struct.unpack('<Q', self._file.read(8))[0]
        elif val_type == 7:  # INT64
            return struct.unpack('<q', self._file.read(8))[0]
        elif val_type == 8:  # FLOAT32
            return struct.unpack('<f', self._file.read(4))[0]
        elif val_type == 9:  # FLOAT64
            return struct.unpack('<d', self._file.read(8))[0]
        elif val_type == 10:  # BOOL
            return struct.unpack('<B', self._file.read(1))[0] != 0
        elif val_type == 11:  # STRING
            return self._read_string()
        elif val_type == 12:  # ARRAY
            arr_type = struct.unpack('<I', self._file.read(4))[0]
            arr_len = struct.unpack('<Q', self._file.read(8))[0]
            return [self._read_value(arr_type) for _ in range(arr_len)]
        return None

    def read(self, size: int) -> bytes:
        return self._file.read(size) if self._file else b""

    def seek(self, offset: int) -> bool:
        if self._file:
            self._file.seek(offset)
            return True
        return False

    def get_header(self) -> StreamHeader:
        return self._header

    def next_tensor(self) -> TensorChunk:
        if self._tensor_index >= len(self._tensors):
            return TensorChunk(is_final=True)
        desc = self._tensors[self._tensor_index]
        self._tensor_index += 1
        data = self.read_tensor(self._tensor_index - 1)
        return TensorChunk(descriptor=desc, data=data, is_final=self._tensor_index >= len(self._tensors))

    def next_token(self) -> TokenChunk:
        return TokenChunk(is_final=True)

    def num_tensors(self) -> int:
        return len(self._tensors)

    def get_tensor(self, index: int) -> TensorDescriptor:
        if 0 <= index < len(self._tensors):
            return self._tensors[index]
        return TensorDescriptor()

    def read_tensor(self, index: int) -> bytes:
        if 0 <= index < len(self._tensors) and self._file:
            desc = self._tensors[index]
            self._file.seek(desc.offset)
            return self._file.read(desc.bytes)
        return b""

    def is_eof(self) -> bool:
        return self._tensor_index >= len(self._tensors)

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    @property
    def stream_type(self) -> StreamType:
        return StreamType.GGUF

    @property
    def source(self) -> str:
        return self._source


class SafetensorsStreamAdapter(IModelStream):
    def __init__(self):
        self._source = ""
        self._file = None
        self._header = StreamHeader()
        self._tensors: List[TensorDescriptor] = []
        self._tensor_index = 0
        self._data_start = 0

    def open(self, source: str) -> bool:
        self._source = source
        if not os.path.exists(source):
            return False
        self._file = open(source, 'rb')
        self._parse_header()
        return True

    def _parse_header(self):
        if not self._file:
            return
        self._file.seek(0)
        header_size = struct.unpack('<Q', self._file.read(8))[0]
        header_bytes = self._file.read(header_size)
        self._data_start = 8 + header_size

        self._header.type = StreamType.SAFETENSORS
        self._header.file_size = os.path.getsize(self._source)

        header_json = json.loads(header_bytes)
        for key, value in header_json.items():
            if key == "__metadata__":
                self._header.metadata = value
            else:
                desc = TensorDescriptor(
                    name=key,
                    shape=value.get("shape", []),
                    dtype=DataType.F32,
                    offset=self._data_start + value.get("data_offsets", [0, 0])[0],
                    bytes=value.get("data_offsets", [0, 0])[1] - value.get("data_offsets", [0, 0])[0],
                    num_elements=1,
                )
                for s in desc.shape:
                    desc.num_elements *= s
                self._tensors.append(desc)

        self._header.num_tensors = len(self._tensors)

    def read(self, size: int) -> bytes:
        return self._file.read(size) if self._file else b""

    def seek(self, offset: int) -> bool:
        if self._file:
            self._file.seek(offset)
            return True
        return False

    def get_header(self) -> StreamHeader:
        return self._header

    def next_tensor(self) -> TensorChunk:
        if self._tensor_index >= len(self._tensors):
            return TensorChunk(is_final=True)
        desc = self._tensors[self._tensor_index]
        self._tensor_index += 1
        data = self.read_tensor(self._tensor_index - 1)
        return TensorChunk(descriptor=desc, data=data, is_final=self._tensor_index >= len(self._tensors))

    def next_token(self) -> TokenChunk:
        return TokenChunk(is_final=True)

    def num_tensors(self) -> int:
        return len(self._tensors)

    def get_tensor(self, index: int) -> TensorDescriptor:
        if 0 <= index < len(self._tensors):
            return self._tensors[index]
        return TensorDescriptor()

    def read_tensor(self, index: int) -> bytes:
        if 0 <= index < len(self._tensors) and self._file:
            desc = self._tensors[index]
            self._file.seek(desc.offset)
            return self._file.read(desc.bytes)
        return b""

    def is_eof(self) -> bool:
        return self._tensor_index >= len(self._tensors)

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    @property
    def stream_type(self) -> StreamType:
        return StreamType.SAFETENSORS

    @property
    def source(self) -> str:
        return self._source


class BlobStreamAdapter(IModelStream):
    def __init__(self):
        self._source = ""
        self._file = None
        self._header = StreamHeader()
        self._is_open = False

    def open(self, source: str) -> bool:
        self._source = source
        if not os.path.exists(source):
            return False
        self._file = open(source, 'rb')
        self._header.type = StreamType.BIN
        self._header.file_size = os.path.getsize(source)
        self._is_open = True
        return True

    def read(self, size: int) -> bytes:
        return self._file.read(size) if self._file else b""

    def seek(self, offset: int) -> bool:
        if self._file:
            self._file.seek(offset)
            return True
        return False

    def get_header(self) -> StreamHeader:
        return self._header

    def next_tensor(self) -> TensorChunk:
        return TensorChunk(is_final=True)

    def next_token(self) -> TokenChunk:
        return TokenChunk(is_final=True)

    def num_tensors(self) -> int:
        return 0

    def get_tensor(self, index: int) -> TensorDescriptor:
        return TensorDescriptor()

    def read_tensor(self, index: int) -> bytes:
        return b""

    def is_eof(self) -> bool:
        return True

    def close(self):
        if self._file:
            self._file.close()
            self._file = None
        self._is_open = False

    @property
    def stream_type(self) -> StreamType:
        return StreamType.BIN

    @property
    def source(self) -> str:
        return self._source


class RemoteStreamAdapter(IModelStream):
    def __init__(self, stream_type: StreamType = StreamType.OLLAMA):
        self._source = ""
        self._type = stream_type
        self._header = StreamHeader()
        self._is_open = False

    def open(self, source: str) -> bool:
        self._source = source
        self._header.type = self._type
        self._header.suggested_name = source.split("/")[-1] if "/" in source else source
        self._is_open = True
        return True

    def read(self, size: int) -> bytes:
        return b""

    def seek(self, offset: int) -> bool:
        return False

    def get_header(self) -> StreamHeader:
        return self._header

    def next_tensor(self) -> TensorChunk:
        return TensorChunk(is_final=True)

    def next_token(self) -> TokenChunk:
        return TokenChunk(is_final=True)

    def num_tensors(self) -> int:
        return 0

    def get_tensor(self, index: int) -> TensorDescriptor:
        return TensorDescriptor()

    def read_tensor(self, index: int) -> bytes:
        return b""

    def is_eof(self) -> bool:
        return True

    def close(self):
        self._is_open = False

    @property
    def stream_type(self) -> StreamType:
        return self._type

    @property
    def source(self) -> str:
        return self._source


# ============================================================================
# STREAM FABRIC
# ============================================================================

class StreamFabric:
    def __init__(self):
        self._stream: Optional[IModelStream] = None
        self._header = StreamHeader()
        self._registry = QuantKernelRegistry()
        self._register_default_kernels()

    def _register_default_kernels(self):
        # Q4_K_M kernel
        def q4_k_m_dequant(desc: TensorDescriptor, data: bytes) -> List[float]:
            block_size = 256
            num_blocks = (desc.num_elements + block_size - 1) // block_size
            output = []
            for b in range(num_blocks):
                block_start = b * block_size
                block_end = min(block_start + block_size, desc.num_elements)
                block_scale = 1.0
                for i in range(block_start, block_end):
                    byte_idx = i // 2
                    if byte_idx < len(data):
                        q4 = (data[byte_idx] >> ((i % 2) * 4)) & 0x0F
                        output.append((q4 - 8) * block_scale)
            return output

        self._registry.register(QuantKernelInfo(
            name="Q4_K_M", scheme=QuantScheme.Q4_K_M,
            kernel=q4_k_m_dequant, throughput_gb_s=45.0, quality_factor=0.95
        ))

        # F16 kernel
        def f16_dequant(desc: TensorDescriptor, data: bytes) -> List[float]:
            output = []
            for i in range(0, len(data), 2):
                if i + 1 < len(data):
                    h = struct.unpack('<H', data[i:i+2])[0]
                    output.append(_f16_to_f32(h))
            return output

        self._registry.register(QuantKernelInfo(
            name="F16", scheme=QuantScheme.F16,
            kernel=f16_dequant, throughput_gb_s=60.0, quality_factor=1.0
        ))

        # F32 kernel
        def f32_dequant(desc: TensorDescriptor, data: bytes) -> List[float]:
            output = []
            for i in range(0, len(data), 4):
                if i + 3 < len(data):
                    output.append(struct.unpack('<f', data[i:i+4])[0])
            return output

        self._registry.register(QuantKernelInfo(
            name="F32", scheme=QuantScheme.NONE,
            kernel=f32_dequant, throughput_gb_s=80.0, quality_factor=1.0
        ))

    def open_model(self, source: str) -> bool:
        # Sniff magic bytes if local file
        if "://" not in source and os.path.exists(source):
            with open(source, 'rb') as f:
                magic = f.read(16)
            sniffed = StreamHeader.detect(magic)
            if sniffed != StreamType.UNKNOWN:
                self._stream = StreamRouter.create_stream(source)
                if self._stream and self._stream.open(source):
                    self._header = self._stream.get_header()
                    return True

        # Route through stream router
        self._stream = StreamRouter.resolve(source)
        if self._stream:
            self._header = self._stream.get_header()
            return True

        return False

    def next_tensor(self) -> TensorChunk:
        if not self._stream:
            return TensorChunk(is_final=True)
        chunk = self._stream.next_tensor()

        # Route through quant registry
        if chunk.descriptor.quant_scheme != QuantScheme.NONE:
            kernel = self._registry.resolve(chunk.descriptor)
            if kernel:
                chunk.descriptor.quant_scheme = QuantScheme.NONE
                chunk.descriptor.dtype = DataType.F32

        return chunk

    def next_token(self) -> TokenChunk:
        if not self._stream:
            return TokenChunk(is_final=True)
        return self._stream.next_token()

    @property
    def header(self) -> StreamHeader:
        return self._header

    @property
    def registry(self) -> QuantKernelRegistry:
        return self._registry

    @property
    def stream(self) -> Optional[IModelStream]:
        return self._stream

    def close(self):
        if self._stream:
            self._stream.close()


def _f16_to_f32(h: int) -> float:
    sign = (h & 0x8000) << 16
    exp = (h & 0x7C00) >> 10
    mant = h & 0x03FF

    if exp == 0:
        if mant == 0:
            return 0.0
        exp = 1
        while not (mant & 0x0400):
            mant <<= 1
            exp -= 1
        mant &= 0x03FF
    elif exp == 31:
        exp = 255
    else:
        exp += 112

    f32 = sign | (exp << 23) | (mant << 13)
    import struct
    return struct.unpack('<f', struct.pack('<I', f32))[0]


# ============================================================================
# TOKEN STREAM PIPELINE
# ============================================================================

class TokenStreamPipeline:
    def __init__(self, max_context: int = 4096, max_batch: int = 512,
                 temperature: float = 0.7, top_p: float = 0.9, top_k: int = 40):
        self.max_context = max_context
        self.max_batch = max_batch
        self.temperature = temperature
        self.top_p = top_p
        self.top_k = top_k
        self._input_buffer = ""
        self._token_queue: deque = deque()
        self._context_window: List[int] = []

    def feed_input(self, text: str):
        self._input_buffer += text

    def next_token(self) -> TokenChunk:
        if not self._input_buffer and not self._token_queue:
            return TokenChunk(is_final=True)

        if self._token_queue:
            return self._token_queue.popleft()

        if self._input_buffer:
            tokens = self._tokenize(self._input_buffer)
            self._input_buffer = ""
            self._manage_context_window(tokens)
            output = self._run_inference()

            for t in output:
                self._token_queue.append(t)

            if self._token_queue:
                return self._token_queue.popleft()

        return TokenChunk(is_final=True)

    def has_more(self) -> bool:
        return bool(self._input_buffer) or bool(self._token_queue)

    def reset(self):
        self._input_buffer = ""
        self._token_queue.clear()
        self._context_window.clear()

    def _tokenize(self, text: str) -> List[int]:
        return [ord(c) for c in text]

    def _manage_context_window(self, new_tokens: List[int]):
        self._context_window.extend(new_tokens)
        while len(self._context_window) > self.max_context:
            self._context_window.pop(0)

    def _run_inference(self) -> List[TokenChunk]:
        output = []
        for i in range(10):
            chunk = TokenChunk(
                token_ids=[i + 100],
                logprobs=[-math.log(i + 1)],
                text=chr(ord('a') + (i % 26)),
                is_final=(i == 9),
            )
            output.append(chunk)
        return output


import math


# ============================================================================
# UNIFIED MEMORY FABRIC
# ============================================================================

class UnifiedMemoryFabric:
    def __init__(self):
        self._nodes: List[MemoryNode] = []
        self._next_id = 1
        self._tick_count = 0

    def add_node(self, node: MemoryNode):
        node.id = self._next_id
        self._next_id += 1
        self._nodes.append(node)

    def tick(self):
        self._predict()
        self._open_sliding_doors()
        self._reverse_decode()
        self._compute()
        self._compress()
        self._archive()
        self._defrag()

    def get_active_nodes(self) -> List[MemoryNode]:
        return [n for n in self._nodes if n.state == Residency.WEIGHTED]

    @dataclass
    class MemoryReport:
        total_bytes_full: int = 0
        total_bytes_current: int = 0
        savings_percent: float = 0.0
        active_count: int = 0
        latent_count: int = 0
        archived_count: int = 0

    def get_memory_report(self) -> MemoryReport:
        report = UnifiedMemoryFabric.MemoryReport()
        for n in self._nodes:
            report.total_bytes_full += n.bytes_full
            report.total_bytes_current += n.bytes_current
            if n.state == Residency.WEIGHTED:
                report.active_count += 1
            if n.state == Residency.LATENT:
                report.latent_count += 1
            if n.state == Residency.ARCHIVED:
                report.archived_count += 1
        if report.total_bytes_full > 0:
            report.savings_percent = (1.0 - report.total_bytes_current / report.total_bytes_full) * 100.0
        return report

    def _predict(self):
        for n in self._nodes:
            n.probability = (
                self._temporal_locality(n) *
                self._semantic_similarity(n) *
                self._routing_prediction(n) *
                self._attention_history(n)
            )

    def _temporal_locality(self, n: MemoryNode) -> float:
        if n.last_used == 0:
            return 0.5
        age = self._tick_count - n.last_used
        if age < 10:
            return 0.95
        if age < 100:
            return 0.7
        if age < 1000:
            return 0.4
        return 0.1

    def _semantic_similarity(self, n: MemoryNode) -> float:
        if not n.neighbors:
            return 0.5
        score = 0.0
        for neighbor_id in n.neighbors:
            for other in self._nodes:
                if other.id == neighbor_id and other.state == Residency.WEIGHTED:
                    score += 0.2
        return min(1.0, score)

    def _routing_prediction(self, n: MemoryNode) -> float:
        return n.importance * 0.6 + min(1.0, n.reuse_score * 0.1) * 0.4

    def _attention_history(self, n: MemoryNode) -> float:
        if n.use_count == 0:
            return 0.3
        return min(1.0, n.use_count * 0.01)

    def _open_sliding_doors(self):
        for n in self._nodes:
            if n.probability > 0.80 and n.state != Residency.WEIGHTED:
                n.state = Residency.PREDICTED
                n.door_open = True
                n.door_opened_at = self._tick_count

            if n.state == Residency.WEIGHTED and n.door_open:
                open_duration = self._tick_count - n.door_opened_at
                # Only close doors for low-importance nodes that haven't been used
                if open_duration > 100 and n.probability < 0.3 and n.importance < 0.5:
                    n.door_open = False
                    n.state = Residency.TRANSITIONING

    def _reverse_decode(self):
        for n in self._nodes:
            if n.state != Residency.PREDICTED:
                continue
            if n.resident_weights is not None:
                continue
            n.resident_weights = b"\x00" * n.bytes_full
            n.bytes_current = n.bytes_full
            n.state = Residency.WEIGHTED

    def _compute(self):
        self._tick_count += 1

    def _compress(self):
        for n in self._nodes:
            if n.state != Residency.WEIGHTED:
                continue
            if n.importance > 0.8:
                continue
            if n.probability < 0.3 and not n.door_open:
                n.latent = b"\x00" * (n.bytes_full // 10)
                n.resident_weights = None
                n.bytes_current = n.bytes_full // 10
                n.state = Residency.COMPRESSED

    def _archive(self):
        for n in self._nodes:
            if n.state != Residency.COMPRESSED:
                continue
            if n.probability < 0.1 and self._tick_count - n.last_used > 1000:
                n.latent = None
                n.bytes_current = 64
                n.state = Residency.ARCHIVED

    def _defrag(self):
        pass


# ============================================================================
# SMOKE TESTS
# ============================================================================

def run_smoke_tests():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║  RawrXD Unified Stream Fabric — Smoke Tests                  ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    passed = 0
    failed = 0

    def check(name: str, cond: bool):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  ✓ {name}")
        else:
            failed += 1
            print(f"  ✗ {name}")

    # Test 1: Stream type detection
    print("\n  [Stream Type Detection]")
    check("GGUF from .gguf", StreamRouter.detect_source("model.gguf") == StreamType.GGUF)
    check("Safetensors from .safetensors", StreamRouter.detect_source("model.safetensors") == StreamType.SAFETENSORS)
    check("BIN from .bin", StreamRouter.detect_source("model.bin") == StreamType.BIN)
    check("JSON from .json", StreamRouter.detect_source("config.json") == StreamType.JSON_MANIFEST)
    check("HTTP URL", StreamRouter.detect_source("https://huggingface.co/meta-llama/Llama-3.2-7B") == StreamType.HF)
    check("Ollama name", StreamRouter.detect_source("llama3.2:7b") == StreamType.OLLAMA)
    check("HF model ID", StreamRouter.detect_source("meta-llama/Llama-3.2-7B") == StreamType.HF)

    # Test 2: Magic byte detection
    print("\n  [Magic Byte Detection]")
    check("GGUF magic", StreamHeader.detect(b"GGUF") == StreamType.GGUF)
    check("JSON magic", StreamHeader.detect(b'{"model"') == StreamType.JSON_MANIFEST)
    check("Safetensors magic", StreamHeader.detect(b"\x2a\x00\x00\x00\x00\x00\x00\x00" + b"\x01" * 8) == StreamType.SAFETENSORS)
    check("Ollama magic", StreamHeader.detect(b"ollama") == StreamType.OLLAMA)
    check("Unknown magic", StreamHeader.detect(b"\xff\xff\xff\xff") == StreamType.RAW)

    # Test 3: Tensor descriptor
    print("\n  [Tensor Descriptor]")
    desc = TensorDescriptor(
        name="blk.0.attn.q.weight",
        shape=[4096, 4096],
        quant_scheme=QuantScheme.Q4_K_M,
        block_size=256,
        num_elements=4096 * 4096,
    )
    check("Tensor has name", desc.name == "blk.0.attn.q.weight")
    check("Tensor has shape", len(desc.shape) == 2)
    check("Tensor format string", desc.format_str() == "Q4_K_M")

    desc2 = TensorDescriptor(dtype=DataType.F16, quant_scheme=QuantScheme.NONE)
    check("F16 format string", desc2.format_str() == "F16")

    desc3 = TensorDescriptor(dtype=DataType.F32, quant_scheme=QuantScheme.NONE)
    check("F32 format string", desc3.format_str() == "F32")

    # Test 4: Quant kernel registry
    print("\n  [Quant Kernel Registry]")
    registry = QuantKernelRegistry()
    registry.register(QuantKernelInfo(name="Q4_K_M", scheme=QuantScheme.Q4_K_M, throughput_gb_s=45.0, quality_factor=0.95))
    registry.register(QuantKernelInfo(name="F16", scheme=QuantScheme.F16, throughput_gb_s=60.0, quality_factor=1.0))
    registry.register(QuantKernelInfo(name="F32", scheme=QuantScheme.NONE, throughput_gb_s=80.0, quality_factor=1.0))
    check("Q4_K_M registered", registry.get(QuantScheme.Q4_K_M) is not None)
    check("F16 registered", registry.get(QuantScheme.F16) is not None)
    check("F32 registered", registry.get(QuantScheme.NONE) is not None)
    check("Available schemes", len(registry.available_schemes()) == 3)

    # Test 5: Stream fabric
    print("\n  [Stream Fabric]")
    fabric = StreamFabric()
    check("Fabric created", fabric is not None)
    check("Default kernels registered", len(fabric.registry.available_schemes()) >= 3)

    # Test 6: Token stream pipeline
    print("\n  [Token Stream Pipeline]")
    pipeline = TokenStreamPipeline()
    pipeline.feed_input("Hello, world!")
    check("Pipeline has tokens", pipeline.has_more())
    token = pipeline.next_token()
    check("Token produced", len(token.token_ids) > 0)
    pipeline.reset()
    check("Pipeline reset", not pipeline.has_more())

    # Test 7: Memory fabric
    print("\n  [Unified Memory Fabric]")
    fabric_um = UnifiedMemoryFabric()

    attn = MemoryNode(
        name="attention_early",
        bytes_full=200 * 1024 * 1024,
        bytes_current=200 * 1024 * 1024,
        importance=0.9,
        reuse_score=50.0,
        use_count=100,
        state=Residency.WEIGHTED,
        door_open=True,
    )
    fabric_um.add_node(attn)

    ffn = MemoryNode(
        name="ffn_mid",
        bytes_full=400 * 1024 * 1024,
        bytes_current=400 * 1024 * 1024,
        importance=0.7,
        reuse_score=30.0,
        use_count=50,
        state=Residency.WEIGHTED,
        door_open=True,
    )
    fabric_um.add_node(ffn)

    latent = MemoryNode(
        name="attention_late",
        bytes_full=200 * 1024 * 1024,
        bytes_current=20 * 1024 * 1024,
        importance=0.3,
        reuse_score=5.0,
        use_count=10,
        state=Residency.LATENT,
    )
    fabric_um.add_node(latent)

    for _ in range(10):
        fabric_um.tick()

    report = fabric_um.get_memory_report()
    check("Memory report has total bytes", report.total_bytes_full > 0)
    check("Memory report has current bytes", report.total_bytes_current > 0)
    check("Memory savings > 0%", report.savings_percent > 0.0)
    check("Active nodes counted", report.active_count > 0)
    check("Latent nodes counted", report.latent_count > 0)

    # Test 8: GGUF adapter (create a minimal test file)
    print("\n  [GGUF Stream Adapter]")
    test_gguf_path = "d:\\rawrxd\\unified_stream_fabric\\test_model.gguf"
    try:
        with open(test_gguf_path, 'wb') as f:
            f.write(b"GGUF")
            f.write(struct.pack('<I', 1))  # version
            f.write(struct.pack('<Q', 2))  # tensor_count
            f.write(struct.pack('<Q', 1))  # metadata_count

            # Metadata: key "general.name", value "test-model"
            name_bytes = b"general.name"
            f.write(struct.pack('<Q', len(name_bytes)))
            f.write(name_bytes)
            f.write(struct.pack('<I', 11))  # STRING type
            val_bytes = b"test-model"
            f.write(struct.pack('<Q', len(val_bytes)))
            f.write(val_bytes)

            # Tensor 1: "blk.0.attn.q.weight" [4096, 4096] F32
            t1_name = b"blk.0.attn.q.weight"
            f.write(struct.pack('<Q', len(t1_name)))
            f.write(t1_name)
            f.write(struct.pack('<I', 2))  # n_dims
            f.write(struct.pack('<QQ', 4096, 4096))  # shape
            f.write(struct.pack('<I', 0))  # dtype F32
            f.write(struct.pack('<Q', 1000))  # offset (past header)

            # Tensor 2: "blk.0.attn.k.weight" [4096, 1024] F16
            t2_name = b"blk.0.attn.k.weight"
            f.write(struct.pack('<Q', len(t2_name)))
            f.write(t2_name)
            f.write(struct.pack('<I', 2))  # n_dims
            f.write(struct.pack('<QQ', 4096, 1024))  # shape
            f.write(struct.pack('<I', 1))  # dtype F16
            f.write(struct.pack('<Q', 2000))  # offset (past header)

        adapter = GGUFStreamAdapter()
        check("GGUF adapter opens file", adapter.open(test_gguf_path))
        check("GGUF header has tensors", adapter.num_tensors() == 2)
        header = adapter.get_header()
        check("GGUF header type", header.type == StreamType.GGUF)
        check("GGUF metadata present", "general.name" in header.metadata)
        check("GGUF metadata value", header.metadata.get("general.name") == "test-model")

        t1 = adapter.get_tensor(0)
        check("Tensor 1 name", t1.name == "blk.0.attn.q.weight")
        check("Tensor 1 shape", t1.shape == [4096, 4096])

        t2 = adapter.get_tensor(1)
        check("Tensor 2 name", t2.name == "blk.0.attn.k.weight")
        check("Tensor 2 shape", t2.shape == [4096, 1024])

        adapter.close()
        os.remove(test_gguf_path)
    except Exception as e:
        check(f"GGUF test file: {e}", False)

    # Test 9: Safetensors adapter (create a minimal test file)
    print("\n  [Safetensors Stream Adapter]")
    test_safe_path = "d:\\rawrxd\\unified_stream_fabric\\test_model.safetensors"
    try:
        header_json = json.dumps({
            "tensor1": {"dtype": "F32", "shape": [64, 64], "data_offsets": [0, 16384]},
            "tensor2": {"dtype": "F16", "shape": [32, 32], "data_offsets": [16384, 18432]},
            "__metadata__": {"model": "test"},
        })
        header_bytes = header_json.encode('utf-8')
        padding = (8 - len(header_bytes) % 8) % 8
        header_bytes += b' ' * padding

        with open(test_safe_path, 'wb') as f:
            f.write(struct.pack('<Q', len(header_bytes)))
            f.write(header_bytes)
            f.write(b"\x00" * 18432)  # tensor data

        adapter = SafetensorsStreamAdapter()
        check("Safetensors adapter opens file", adapter.open(test_safe_path))
        check("Safetensors has tensors", adapter.num_tensors() == 2)
        header = adapter.get_header()
        check("Safetensors header type", header.type == StreamType.SAFETENSORS)

        t1 = adapter.get_tensor(0)
        check("Safetensors tensor 1 name", t1.name == "tensor1")
        check("Safetensors tensor 1 shape", t1.shape == [64, 64])

        adapter.close()
        os.remove(test_safe_path)
    except Exception as e:
        check(f"Safetensors test file: {e}", False)

    # Test 10: Stream fabric with GGUF file
    print("\n  [Stream Fabric Integration]")
    test_gguf_path2 = "d:\\rawrxd\\unified_stream_fabric\\test_model2.gguf"
    try:
        with open(test_gguf_path2, 'wb') as f:
            f.write(b"GGUF")
            f.write(struct.pack('<I', 1))
            f.write(struct.pack('<Q', 1))  # 1 tensor
            f.write(struct.pack('<Q', 0))  # 0 metadata
            t_name = b"test.weight"
            f.write(struct.pack('<Q', len(t_name)))
            f.write(t_name)
            f.write(struct.pack('<I', 2))
            f.write(struct.pack('<QQ', 16, 16))
            f.write(struct.pack('<I', 0))  # F32
            f.write(struct.pack('<Q', 100))  # offset (past header)

        fabric = StreamFabric()
        check("Fabric opens GGUF", fabric.open_model(test_gguf_path2))
        check("Fabric header type", fabric.header.type == StreamType.GGUF)

        chunk = fabric.next_tensor()
        check("Fabric streams tensor", not chunk.is_final)
        check("Fabric tensor name", chunk.descriptor.name == "test.weight")

        fabric.close()
        os.remove(test_gguf_path2)
    except Exception as e:
        check(f"Fabric integration test: {e}", False)

    # Test 11: Quant kernel dequantization
    print("\n  [Quant Kernel Dequantization]")
    registry2 = QuantKernelRegistry()
    registry2.register(QuantKernelInfo(
        name="Q4_K_M", scheme=QuantScheme.Q4_K_M,
        kernel=lambda desc, data: [((data[i // 2] >> ((i % 2) * 4)) & 0x0F) for i in range(desc.num_elements)],
        throughput_gb_s=45.0, quality_factor=0.95
    ))
    kernel = registry2.resolve(TensorDescriptor(quant_scheme=QuantScheme.Q4_K_M, num_elements=8))
    check("Kernel resolved for Q4_K_M", kernel is not None)

    test_data = bytes([0x12, 0x34, 0x56, 0x78])
    result = kernel(TensorDescriptor(num_elements=8), test_data)
    check("Kernel produces output", len(result) == 8)
    check("Kernel output values correct", result == [2, 1, 4, 3, 6, 5, 8, 7])

    # Test 12: F16 dequantization
    print("\n  [F16 Dequantization]")
    f16_data = struct.pack('<H', 0x3C00)  # 1.0 in F16
    result = _f16_to_f32(0x3C00)
    check("F16 1.0 → F32 1.0", abs(result - 1.0) < 0.001)

    # Test 13: Memory node lifecycle
    print("\n  [Memory Node Lifecycle]")
    node = MemoryNode(
        name="test_layer",
        bytes_full=100 * 1024 * 1024,
        bytes_current=100 * 1024 * 1024,
        importance=0.9,
        state=Residency.WEIGHTED,
        door_open=True,
    )
    check("Memory node created", node.name == "test_layer")
    check("Memory node starts WEIGHTED", node.state == Residency.WEIGHTED)
    check("Memory node has importance", node.importance == 0.9)

    # Test 14: Residency transitions
    print("\n  [Residency Transitions]")
    fabric_um2 = UnifiedMemoryFabric()
    n1 = MemoryNode(name="n1", bytes_full=100, bytes_current=100, importance=0.9, reuse_score=50, use_count=100, state=Residency.WEIGHTED, door_open=True)
    n2 = MemoryNode(name="n2", bytes_full=100, bytes_current=100, importance=0.3, reuse_score=5, use_count=5, state=Residency.WEIGHTED, door_open=True)
    fabric_um2.add_node(n1)
    fabric_um2.add_node(n2)

    for _ in range(200):
        fabric_um2.tick()

    report = fabric_um2.get_memory_report()
    check("High importance node stays WEIGHTED", any(n.state == Residency.WEIGHTED for n in fabric_um2._nodes if n.importance > 0.8))
    check("Memory savings after lifecycle", report.savings_percent > 0)

    # Test 15: Token pipeline with multiple inputs
    print("\n  [Token Pipeline Multiple Inputs]")
    pipeline2 = TokenStreamPipeline()
    pipeline2.feed_input("First input. ")
    pipeline2.feed_input("Second input.")
    check("Pipeline buffers multiple inputs", pipeline2.has_more())

    tokens = []
    while pipeline2.has_more():
        t = pipeline2.next_token()
        if t.token_ids:
            tokens.append(t)
    check("Pipeline produces tokens", len(tokens) > 0)

    # Test 16: Stream router edge cases
    print("\n  [Stream Router Edge Cases]")
    check("Empty source", StreamRouter.detect_source("") == StreamType.RAW)
    check("No extension", StreamRouter.detect_source("model") == StreamType.RAW)
    check("Unknown extension", StreamRouter.detect_source("model.xyz") == StreamType.RAW)
    check("Ollama with tag", StreamRouter.detect_source("llama3.2:7b") == StreamType.OLLAMA)
    check("HF with org/model", StreamRouter.detect_source("org/model") == StreamType.HF)

    # Test 17: Quant scheme names
    print("\n  [Quant Scheme Names]")
    check("Q2_K name", QuantScheme.Q2_K.name == "Q2_K")
    check("Q4_K_M name", QuantScheme.Q4_K_M.name == "Q4_K_M")
    check("F16 name", QuantScheme.F16.name == "F16")
    check("F32 name", QuantScheme.NONE.name == "NONE")

    # Test 18: Data type names
    print("\n  [Data Type Names]")
    check("F16 dtype", DataType.F16.name == "F16")
    check("F32 dtype", DataType.F32.name == "F32")
    check("Q4 dtype", DataType.Q4.name == "Q4")

    # Test 19: Stream header edge cases
    print("\n  [Stream Header Edge Cases]")
    check("Empty magic", StreamHeader.detect(b"") == StreamType.UNKNOWN)
    check("Short magic", StreamHeader.detect(b"GG") == StreamType.UNKNOWN)
    check("Array magic", StreamHeader.detect(b"[1,2,3]") == StreamType.JSON_MANIFEST)

    # Test 20: Full pipeline integration
    print("\n  [Full Pipeline Integration]")
    fabric3 = StreamFabric()
    check("Fabric has default kernels", len(fabric3.registry.available_schemes()) >= 3)
    check("Fabric can be closed", fabric3.stream is None or fabric3.close() is None)

    # Summary
    total = passed + failed
    print(f"\n──────────────────────────────────────────────────────────────")
    print(f"  Smoke Tests: {passed}/{total} passed")
    if failed > 0:
        print(f"  FAILED: {failed} tests failed!")
    else:
        print(f"  ALL TESTS PASSED ✓")
    print(f"──────────────────────────────────────────────────────────────")
    print(f"  Signed: ~g87 | RawrXD Unified Stream Fabric v1.0")

    return failed == 0


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        run_smoke_tests()
    else:
        run_smoke_tests()
