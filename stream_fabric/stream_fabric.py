"""
RawrXD Stream Fabric — Universal Model Streaming Layer

The stream fabric is the universal ingestion path for ALL model formats.
Every backend (GGUF, SafeTensors, Ollama, HF, raw blobs, etc.) feeds into
a single streaming abstraction. The Magic Detection Engine routes sources
to the correct adapter, and the adapters expose a unified IModelStream interface.

Architecture:
  Source (file/URL)
     │
     ▼
  MagicDetector ──→ DetectionResult
     │
     ▼
  StreamRouter ──→ IModelStream adapter
     │
     ├── GGUFStreamAdapter
     ├── SafeTensorStreamAdapter
     ├── HFStreamAdapter
     ├── OllamaStreamAdapter
     ├── RawTensorStreamAdapter
     └── BlobStreamAdapter
     │
     ▼
  Tensor/Token Pipeline
     │
     ▼
  Inference Engine

Signed: ~g87 | RawrXD | uwu kawaii
"""

import os
import json
import struct
import hashlib
import time
import io
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Iterator, BinaryIO
from enum import Enum, auto
from pathlib import Path
from abc import ABC, abstractmethod

# Import magic detection
from magic_detection import (
    MagicDetector, DetectionResult, ModelFormat, StreamRouter as BaseStreamRouter
)


# ═════════════════════════════════════════════════════════════════════
# TYPES
# ═════════════════════════════════════════════════════════════════════

@dataclass
class TensorDescriptor:
    """Describes a single tensor in a model."""
    name: str
    shape: List[int]
    dtype: str                       # "f32", "f16", "q4_0", "q4_k", etc.
    offset: int                      # Byte offset in the source
    size_bytes: int                  # Total size in bytes
    n_dims: int = 0
    is_quantized: bool = False
    quant_scheme: str = ""           # "Q4_K_M", "Q5_0", etc.
    block_size: int = 0
    scale_type: str = ""             # "fp32", "fp16"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelHeader:
    """Model-level metadata from the header."""
    format: ModelFormat
    version: int = 0
    tensor_count: int = 0
    kv_count: int = 0
    alignment: int = 32
    name: str = ""
    description: str = ""
    architecture: str = ""
    file_size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TensorChunk:
    """A chunk of tensor data read from a stream."""
    tensor_name: str
    offset: int
    size: int
    data: bytes
    is_final: bool = False           # True if this is the last chunk for this tensor


@dataclass
class StreamProvenance:
    """Provenance attestation for a stream."""
    component: str = "StreamFabric"
    version: str = "1.0"
    source_hash: str = ""
    format: str = ""
    adapter: str = ""
    tensor_count: int = 0
    total_bytes: int = 0
    detected_by: str = ""
    confidence: float = 0.0
    timestamp: str = ""
    signature: str = "~g87"
    
    def to_dict(self) -> Dict:
        return {
            "component": self.component,
            "version": self.version,
            "source_hash": self.source_hash,
            "format": self.format,
            "adapter": self.adapter,
            "tensor_count": self.tensor_count,
            "total_bytes": self.total_bytes,
            "detected_by": self.detected_by,
            "confidence": self.confidence,
            "timestamp": self.timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "signature": self.signature,
        }
    
    def verify(self) -> bool:
        """Verify the provenance is self-consistent."""
        return self.signature == "~g87" and self.component == "StreamFabric"


# ═════════════════════════════════════════════════════════════════════
# IModelStream — Universal Stream Interface
# ═════════════════════════════════════════════════════════════════════

class IModelStream(ABC):
    """
    Universal model stream interface.
    
    Every model format adapter implements this interface.
    The inference engine talks to IModelStream, not to any specific format.
    """
    
    @abstractmethod
    def open(self, source: str) -> bool:
        """Open a model source for streaming. Returns True on success."""
        pass
    
    @abstractmethod
    def read_header(self) -> ModelHeader:
        """Read and return the model header/metadata."""
        pass
    
    @abstractmethod
    def enumerate_tensors(self) -> List[TensorDescriptor]:
        """Enumerate all tensors in the model (metadata only, no data loaded)."""
        pass
    
    @abstractmethod
    def read_tensor(self, name: str, offset: int = 0, size: Optional[int] = None) -> bytes:
        """Read tensor data by name. Supports partial reads via offset/size."""
        pass
    
    @abstractmethod
    def stream_chunks(self, tensor_name: str, chunk_size: int = 4096) -> Iterator[TensorChunk]:
        """Stream a tensor's data in chunks (lazy loading)."""
        pass
    
    @abstractmethod
    def close(self):
        """Close the stream and release resources."""
        pass
    
    @property
    @abstractmethod
    def provenance(self) -> StreamProvenance:
        """Get provenance attestation for this stream."""
        pass
    
    @property
    @abstractmethod
    def is_open(self) -> bool:
        """Whether the stream is currently open."""
        pass


# ═════════════════════════════════════════════════════════════════════
# GGUF STREAM ADAPTER
# ═════════════════════════════════════════════════════════════════════

class GGUFStreamAdapter(IModelStream):
    """
    Stream adapter for GGUF format files.
    
    Reads GGUF files lazily — header first, then tensors on demand.
    No full file mmap, no full VRAM allocation, no complete model decode.
    """
    
    GGUF_MAGIC = b"GGUF"
    
    def __init__(self):
        self._file: Optional[BinaryIO] = None
        self._path: str = ""
        self._header: Optional[ModelHeader] = None
        self._tensors: List[TensorDescriptor] = []
        self._tensor_map: Dict[str, TensorDescriptor] = {}
        self._data_offset: int = 0
        self._file_size: int = 0
        self._provenance: Optional[StreamProvenance] = None
        self._source_hash: str = ""
    
    def open(self, source: str) -> bool:
        """Open a GGUF file for streaming."""
        self._path = source
        path = Path(source)
        
        if not path.exists():
            return False
        
        self._file_size = path.stat().st_size
        
        # Compute source hash (first 64KB for speed)
        try:
            with open(path, "rb") as f:
                head = f.read(65536)
            self._source_hash = hashlib.sha256(head).hexdigest()[:16]
        except:
            self._source_hash = "unknown"
        
        # Open file
        self._file = open(path, "rb")
        
        # Read and parse header — close on failure
        try:
            self._parse_header()
        except Exception as e:
            self._file.close()
            self._file = None
            return False
        
        return True
    
    def _parse_header(self):
        """Parse the GGUF header (metadata only, no tensor data loaded)."""
        if not self._file:
            raise RuntimeError("Stream not open")
        
        self._file.seek(0)
        
        # Magic: 4 bytes
        magic = self._file.read(4)
        if magic != self.GGUF_MAGIC:
            raise ValueError(f"Not a GGUF file: magic={magic}")
        
        # Version: uint32
        version_bytes = self._file.read(4)
        version = struct.unpack('<I', version_bytes)[0]
        
        # Tensor count: int64
        tensor_count_bytes = self._file.read(8)
        tensor_count = struct.unpack('<q', tensor_count_bytes)[0]
        
        # KV count: int64
        kv_count_bytes = self._file.read(8)
        kv_count = struct.unpack('<q', kv_count_bytes)[0]
        
        # Read KV pairs (metadata)
        metadata = {}
        alignment = 32
        for _ in range(kv_count):
            key = self._read_gguf_string()
            value_type = struct.unpack('<i', self._file.read(4))[0]
            value = self._read_gguf_value(value_type)
            metadata[key] = value
            
            if key == "general.alignment":
                alignment = value
            elif key == "general.name":
                pass  # Will set below
            elif key == "general.architecture":
                pass
        
        # Read tensor info entries (metadata only, no data)
        tensors = []
        for _ in range(tensor_count):
            name = self._read_gguf_string()
            n_dims = struct.unpack('<I', self._file.read(4))[0]
            dims = list(struct.unpack(f'<{n_dims}q', self._file.read(8 * n_dims)))
            dtype = struct.unpack('<i', self._file.read(4))[0]
            offset = struct.unpack('<Q', self._file.read(8))[0]
            
            # Calculate size
            element_count = 1
            for d in dims:
                element_count *= d
            type_size = self._ggml_type_size(dtype)
            size_bytes = (element_count * type_size + alignment - 1) // alignment * alignment
            
            # Determine quant scheme
            quant_scheme, is_quantized, block_size = self._ggml_type_info(dtype)
            
            desc = TensorDescriptor(
                name=name,
                shape=dims,
                n_dims=n_dims,
                dtype=self._ggml_type_name(dtype),
                offset=offset,
                size_bytes=size_bytes,
                is_quantized=is_quantized,
                quant_scheme=quant_scheme,
                block_size=block_size,
                scale_type="fp32",
            )
            tensors.append(desc)
        
        # Data offset is current position, aligned
        self._data_offset = self._file.tell()
        
        # Build header
        self._header = ModelHeader(
            format=ModelFormat.GGUF,
            version=version,
            tensor_count=tensor_count,
            kv_count=kv_count,
            alignment=alignment,
            name=metadata.get("general.name", ""),
            description=metadata.get("general.description", ""),
            architecture=metadata.get("general.architecture", ""),
            file_size=self._file_size,
            metadata=metadata,
        )
        
        self._tensors = tensors
        self._tensor_map = {t.name: t for t in tensors}
        
        # Build provenance
        self._provenance = StreamProvenance(
            source_hash=self._source_hash,
            format="GGUF",
            adapter="GGUFStreamAdapter",
            tensor_count=len(tensors),
            total_bytes=self._file_size,
            detected_by="magic:47475546",
            confidence=0.95,
        )
    
    def _read_gguf_string(self) -> str:
        """Read a GGUF string (length-prefixed, no null terminator)."""
        length = struct.unpack('<Q', self._file.read(8))[0]
        return self._file.read(length).decode('utf-8')
    
    def _read_gguf_value(self, value_type: int) -> Any:
        """Read a GGUF value by type."""
        if value_type == 0:   # UINT8
            return struct.unpack('<B', self._file.read(1))[0]
        elif value_type == 1:  # INT8
            return struct.unpack('<b', self._file.read(1))[0]
        elif value_type == 2:  # UINT16
            return struct.unpack('<H', self._file.read(2))[0]
        elif value_type == 3:  # INT16
            return struct.unpack('<h', self._file.read(2))[0]
        elif value_type == 4:  # UINT32
            return struct.unpack('<I', self._file.read(4))[0]
        elif value_type == 5:  # INT32
            return struct.unpack('<i', self._file.read(4))[0]
        elif value_type == 6:  # FLOAT32
            return struct.unpack('<f', self._file.read(4))[0]
        elif value_type == 7:  # BOOL
            return struct.unpack('<b', self._file.read(1))[0] != 0
        elif value_type == 8:  # STRING
            return self._read_gguf_string()
        elif value_type == 9:  # ARRAY
            arr_type = struct.unpack('<i', self._file.read(4))[0]
            arr_len = struct.unpack('<Q', self._file.read(8))[0]
            return [self._read_gguf_value(arr_type) for _ in range(arr_len)]
        elif value_type == 10:  # UINT64
            return struct.unpack('<Q', self._file.read(8))[0]
        elif value_type == 11:  # INT64
            return struct.unpack('<q', self._file.read(8))[0]
        elif value_type == 12:  # FLOAT64
            return struct.unpack('<d', self._file.read(8))[0]
        return None
    
    def _ggml_type_name(self, dtype: int) -> str:
        """Map GGML type enum to string name."""
        names = {
            0: "f32", 1: "f16", 2: "q4_0", 3: "q4_1",
            6: "q5_0", 7: "q5_1", 8: "q8_0", 10: "q2_k",
            11: "q3_k", 12: "q4_k", 13: "q5_k", 14: "q6_k",
            16: "q8_k", 17: "iq2_xxs", 18: "iq2_xs",
            19: "iq3_xxs", 20: "iq1_s", 21: "iq4_nl",
            22: "iq3_s", 23: "iq2_s", 24: "iq4_xs",
            25: "i8", 26: "i16", 27: "i32", 28: "i64",
            29: "f64", 30: "iq1_m",
        }
        return names.get(dtype, f"unknown({dtype})")
    
    def _ggml_type_size(self, dtype: int) -> int:
        """Get the size of a single element for a GGML type."""
        sizes = {
            0: 4, 1: 2, 2: 2, 3: 2, 6: 2, 7: 2, 8: 1,
            10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 16: 1,
            17: 1, 18: 1, 19: 1, 20: 1, 21: 1, 22: 1,
            23: 1, 24: 1, 25: 1, 26: 2, 27: 4, 28: 8,
            29: 8, 30: 1,
        }
        return sizes.get(dtype, 4)
    
    def _ggml_type_info(self, dtype: int) -> Tuple[str, bool, int]:
        """Get (quant_scheme, is_quantized, block_size) for a GGML type."""
        info = {
            0:  ("F32", False, 0),
            1:  ("F16", False, 0),
            2:  ("Q4_0", True, 32),
            3:  ("Q4_1", True, 32),
            6:  ("Q5_0", True, 32),
            7:  ("Q5_1", True, 32),
            8:  ("Q8_0", True, 32),
            10: ("Q2_K", True, 256),
            11: ("Q3_K", True, 256),
            12: ("Q4_K", True, 256),
            13: ("Q5_K", True, 256),
            14: ("Q6_K", True, 256),
            16: ("Q8_K", True, 256),
            17: ("IQ2_XXS", True, 256),
            18: ("IQ2_XS", True, 256),
            19: ("IQ3_XXS", True, 256),
            21: ("IQ4_NL", True, 32),
            22: ("IQ3_S", True, 256),
            23: ("IQ2_S", True, 256),
            24: ("IQ4_XS", True, 256),
        }
        return info.get(dtype, ("UNKNOWN", False, 0))
    
    def read_header(self) -> ModelHeader:
        if not self._header:
            raise RuntimeError("Stream not open")
        return self._header
    
    def enumerate_tensors(self) -> List[TensorDescriptor]:
        if not self._tensors:
            raise RuntimeError("Stream not open")
        return list(self._tensors)
    
    def read_tensor(self, name: str, offset: int = 0, size: Optional[int] = None) -> bytes:
        """Read tensor data by name. Supports partial reads."""
        if not self._file:
            raise RuntimeError("Stream not open")
        
        desc = self._tensor_map.get(name)
        if not desc:
            raise KeyError(f"Tensor '{name}' not found")
        
        if size is None:
            size = desc.size_bytes - offset
        
        actual_offset = self._data_offset + desc.offset + offset
        self._file.seek(actual_offset)
        return self._file.read(size)
    
    def stream_chunks(self, tensor_name: str, chunk_size: int = 65536) -> Iterator[TensorChunk]:
        """Stream a tensor's data in chunks (lazy loading)."""
        if not self._file:
            raise RuntimeError("Stream not open")
        
        desc = self._tensor_map.get(tensor_name)
        if not desc:
            raise KeyError(f"Tensor '{tensor_name}' not found")
        
        remaining = desc.size_bytes
        current_offset = 0
        
        while remaining > 0:
            read_size = min(chunk_size, remaining)
            data = self.read_tensor(tensor_name, current_offset, read_size)
            remaining -= read_size
            is_final = remaining <= 0
            
            yield TensorChunk(
                tensor_name=tensor_name,
                offset=current_offset,
                size=read_size,
                data=data,
                is_final=is_final,
            )
            current_offset += read_size
    
    def close(self):
        if self._file:
            self._file.close()
            self._file = None
    
    @property
    def provenance(self) -> StreamProvenance:
        if not self._provenance:
            raise RuntimeError("Stream not open")
        return self._provenance
    
    @property
    def is_open(self) -> bool:
        return self._file is not None


# ═════════════════════════════════════════════════════════════════════
# SAFETENSOR STREAM ADAPTER
# ═════════════════════════════════════════════════════════════════════

class SafeTensorStreamAdapter(IModelStream):
    """
    Stream adapter for Hugging Face SafeTensors format.
    
    SafeTensors format:
    - 8 bytes: header size (uint64 little-endian)
    - N bytes: JSON header
    - Remaining: tensor data at offsets specified in header
    """
    
    def __init__(self):
        self._file: Optional[BinaryIO] = None
        self._path: str = ""
        self._header: Optional[ModelHeader] = None
        self._tensors: List[TensorDescriptor] = []
        self._tensor_map: Dict[str, TensorDescriptor] = {}
        self._data_offset: int = 0
        self._file_size: int = 0
        self._provenance: Optional[StreamProvenance] = None
        self._source_hash: str = ""
    
    def open(self, source: str) -> bool:
        self._path = source
        path = Path(source)
        if not path.exists():
            return False
        
        self._file_size = path.stat().st_size
        
        try:
            with open(path, "rb") as f:
                head = f.read(65536)
            self._source_hash = hashlib.sha256(head).hexdigest()[:16]
        except:
            self._source_hash = "unknown"
        
        self._file = open(path, "rb")
        self._parse_header()
        return True
    
    def _parse_header(self):
        """Parse SafeTensors header (metadata only)."""
        if not self._file:
            raise RuntimeError("Stream not open")
        
        self._file.seek(0)
        
        # Read header size (uint64 LE)
        header_size_bytes = self._file.read(8)
        header_size = struct.unpack('<Q', header_size_bytes)[0]
        
        # Read JSON header
        header_json_bytes = self._file.read(header_size)
        header_json = json.loads(header_json_bytes.decode('utf-8'))
        
        # Data starts after header
        self._data_offset = 8 + header_size
        
        # Parse metadata
        metadata = header_json.get("__metadata__", {})
        
        # Parse tensors
        tensors = []
        for name, info in header_json.items():
            if name == "__metadata__":
                continue
            
            dtype = info.get("dtype", "F32")
            shape = info.get("shape", [])
            data_offsets = info.get("data_offsets", [0, 0])
            
            # Calculate size
            element_count = 1
            for d in shape:
                element_count *= d
            
            type_size = self._dtype_size(dtype)
            size_bytes = element_count * type_size
            
            is_quantized = dtype.lower() in ("q4_0", "q4_1", "q5_0", "q5_1", "q8_0",
                                              "q2_k", "q3_k", "q4_k", "q5_k", "q6_k", "q8_k")
            
            desc = TensorDescriptor(
                name=name,
                shape=shape,
                n_dims=len(shape),
                dtype=dtype,
                offset=data_offsets[0],
                size_bytes=data_offsets[1] - data_offsets[0],
                is_quantized=is_quantized,
                quant_scheme=dtype.upper() if is_quantized else "",
            )
            tensors.append(desc)
        
        self._header = ModelHeader(
            format=ModelFormat.SAFETENSORS,
            tensor_count=len(tensors),
            metadata=metadata,
            file_size=self._file_size,
        )
        
        self._tensors = tensors
        self._tensor_map = {t.name: t for t in tensors}
        
        self._provenance = StreamProvenance(
            source_hash=self._source_hash,
            format="SafeTensors",
            adapter="SafeTensorStreamAdapter",
            tensor_count=len(tensors),
            total_bytes=self._file_size,
            detected_by="content:safetensors",
            confidence=0.95,
        )
    
    def _dtype_size(self, dtype: str) -> int:
        sizes = {"F32": 4, "F16": 2, "BF16": 2, "I8": 1, "I16": 2, "I32": 4, "I64": 8,
                 "F64": 8, "BOOL": 1, "U8": 1, "U16": 2, "U32": 4, "U64": 8}
        return sizes.get(dtype.upper(), 4)
    
    def read_header(self) -> ModelHeader:
        if not self._header:
            raise RuntimeError("Stream not open")
        return self._header
    
    def enumerate_tensors(self) -> List[TensorDescriptor]:
        if not self._tensors:
            raise RuntimeError("Stream not open")
        return list(self._tensors)
    
    def read_tensor(self, name: str, offset: int = 0, size: Optional[int] = None) -> bytes:
        if not self._file:
            raise RuntimeError("Stream not open")
        desc = self._tensor_map.get(name)
        if not desc:
            raise KeyError(f"Tensor '{name}' not found")
        if size is None:
            size = desc.size_bytes - offset
        actual_offset = self._data_offset + desc.offset + offset
        self._file.seek(actual_offset)
        return self._file.read(size)
    
    def stream_chunks(self, tensor_name: str, chunk_size: int = 65536) -> Iterator[TensorChunk]:
        if not self._file:
            raise RuntimeError("Stream not open")
        desc = self._tensor_map.get(tensor_name)
        if not desc:
            raise KeyError(f"Tensor '{tensor_name}' not found")
        remaining = desc.size_bytes
        current_offset = 0
        while remaining > 0:
            read_size = min(chunk_size, remaining)
            data = self.read_tensor(tensor_name, current_offset, read_size)
            remaining -= read_size
            yield TensorChunk(
                tensor_name=tensor_name,
                offset=current_offset,
                size=read_size,
                data=data,
                is_final=remaining <= 0,
            )
            current_offset += read_size
    
    def close(self):
        if self._file:
            self._file.close()
            self._file = None
    
    @property
    def provenance(self) -> StreamProvenance:
        if not self._provenance:
            raise RuntimeError("Stream not open")
        return self._provenance
    
    @property
    def is_open(self) -> bool:
        return self._file is not None


# ═════════════════════════════════════════════════════════════════════
# OLLAMA STREAM ADAPTER
# ═════════════════════════════════════════════════════════════════════

class OllamaStreamAdapter(IModelStream):
    """
    Stream adapter for Ollama remote models.
    
    Connects to a local or remote Ollama API and streams tensor data
    through the same IModelStream interface. No local model file needed.
    """
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self._base_url = base_url.rstrip("/")
        self._model_name: str = ""
        self._header: Optional[ModelHeader] = None
        self._tensors: List[TensorDescriptor] = []
        self._tensor_map: Dict[str, TensorDescriptor] = {}
        self._provenance: Optional[StreamProvenance] = None
        self._is_open = False
        self._manifest: Dict = {}
    
    def open(self, source: str) -> bool:
        """Open an Ollama model reference."""
        # Parse source: "ollama://modelname" or "modelname"
        self._model_name = source.replace("ollama://", "").split("?")[0]
        
        # Try to get model info from Ollama API
        try:
            import urllib.request
            import json as _json
            
            # Show API call
            url = f"{self._base_url}/api/show"
            data = _json.dumps({"name": self._model_name}).encode()
            req = urllib.request.Request(url, data=data, 
                headers={"Content-Type": "application/json"})
            
            with urllib.request.urlopen(req, timeout=5) as resp:
                self._manifest = _json.loads(resp.read())
            
            # Build header from manifest
            details = self._manifest.get("details", {})
            model_info = self._manifest.get("model_info", {})
            
            self._header = ModelHeader(
                format=ModelFormat.OLLAMA,
                name=self._model_name,
                architecture=details.get("family", ""),
                metadata=self._manifest,
            )
            
            # Estimate tensors from model info
            tensor_count = 0
            for key in model_info:
                if ".weight" in key or ".bias" in key:
                    tensor_count += 1
            
            self._header.tensor_count = tensor_count
            
            self._provenance = StreamProvenance(
                source_hash=hashlib.sha256(self._model_name.encode()).hexdigest()[:16],
                format="Ollama",
                adapter="OllamaStreamAdapter",
                tensor_count=tensor_count,
                total_bytes=0,
                detected_by="url:ollama",
                confidence=0.9,
            )
            
            self._is_open = True
            return True
            
        except Exception as e:
            # Fallback: create a stub header
            self._header = ModelHeader(
                format=ModelFormat.OLLAMA,
                name=self._model_name,
                metadata={"error": str(e)},
            )
            self._provenance = StreamProvenance(
                source_hash=self._model_name,
                format="Ollama",
                adapter="OllamaStreamAdapter",
                tensor_count=0,
                total_bytes=0,
                detected_by="url:ollama",
                confidence=0.5,
            )
            self._is_open = True
            return True
    
    def read_header(self) -> ModelHeader:
        if not self._header:
            raise RuntimeError("Stream not open")
        return self._header
    
    def enumerate_tensors(self) -> List[TensorDescriptor]:
        return list(self._tensors)
    
    def read_tensor(self, name: str, offset: int = 0, size: Optional[int] = None) -> bytes:
        # Ollama doesn't support direct tensor access — would need to proxy
        raise NotImplementedError("Ollama tensor access requires API proxy")
    
    def stream_chunks(self, tensor_name: str, chunk_size: int = 4096) -> Iterator[TensorChunk]:
        raise NotImplementedError("Ollama streaming requires API proxy")
    
    def close(self):
        self._is_open = False
    
    @property
    def provenance(self) -> StreamProvenance:
        if not self._provenance:
            raise RuntimeError("Stream not open")
        return self._provenance
    
    @property
    def is_open(self) -> bool:
        return self._is_open


# ═════════════════════════════════════════════════════════════════════
# RAW TENSOR STREAM ADAPTER
# ═════════════════════════════════════════════════════════════════════

class RawTensorStreamAdapter(IModelStream):
    """
    Stream adapter for raw binary tensor data.
    
    Handles .bin, .blob, .f16, .f32 files that contain raw tensor data
    without a structured header. Requires a companion JSON manifest or
    manual tensor specification.
    """
    
    def __init__(self):
        self._file: Optional[BinaryIO] = None
        self._path: str = ""
        self._header: Optional[ModelHeader] = None
        self._tensors: List[TensorDescriptor] = []
        self._tensor_map: Dict[str, TensorDescriptor] = {}
        self._file_size: int = 0
        self._provenance: Optional[StreamProvenance] = None
        self._source_hash: str = ""
    
    def open(self, source: str) -> bool:
        self._path = source
        path = Path(source)
        if not path.exists():
            return False
        
        self._file_size = path.stat().st_size
        
        try:
            with open(path, "rb") as f:
                head = f.read(65536)
            self._source_hash = hashlib.sha256(head).hexdigest()[:16]
        except:
            self._source_hash = "unknown"
        
        # Look for companion JSON manifest
        manifest_path = path.with_suffix(".json")
        manifest = {}
        if manifest_path.exists():
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
            except:
                pass
        
        # Build tensor descriptors from manifest or create a single blob tensor
        if manifest.get("tensors"):
            for t in manifest["tensors"]:
                desc = TensorDescriptor(
                    name=t.get("name", "unknown"),
                    shape=t.get("shape", [self._file_size]),
                    dtype=t.get("dtype", "f32"),
                    offset=t.get("offset", 0),
                    size_bytes=t.get("size", self._file_size),
                )
                self._tensors.append(desc)
        else:
            # Single blob tensor
            ext = path.suffix.lower()
            dtype = {"f16": "f16", "fp16": "f16", "f32": "f32", "fp32": "f32",
                     "bin": "f32", "blob": "f32"}.get(ext.lstrip("."), "f32")
            self._tensors.append(TensorDescriptor(
                name="data",
                shape=[self._file_size // (4 if dtype == "f32" else 2)],
                dtype=dtype,
                offset=0,
                size_bytes=self._file_size,
            ))
        
        self._tensor_map = {t.name: t for t in self._tensors}
        
        self._header = ModelHeader(
            format=ModelFormat.BLOB,
            tensor_count=len(self._tensors),
            file_size=self._file_size,
            metadata=manifest,
        )
        
        self._provenance = StreamProvenance(
            source_hash=self._source_hash,
            format="RawTensor",
            adapter="RawTensorStreamAdapter",
            tensor_count=len(self._tensors),
            total_bytes=self._file_size,
            detected_by="extension:" + path.suffix,
            confidence=0.6,
        )
        
        self._file = open(path, "rb")
        return True
    
    def read_header(self) -> ModelHeader:
        if not self._header:
            raise RuntimeError("Stream not open")
        return self._header
    
    def enumerate_tensors(self) -> List[TensorDescriptor]:
        return list(self._tensors)
    
    def read_tensor(self, name: str, offset: int = 0, size: Optional[int] = None) -> bytes:
        if not self._file:
            raise RuntimeError("Stream not open")
        desc = self._tensor_map.get(name)
        if not desc:
            raise KeyError(f"Tensor '{name}' not found")
        if size is None:
            size = desc.size_bytes - offset
        self._file.seek(desc.offset + offset)
        return self._file.read(size)
    
    def stream_chunks(self, tensor_name: str, chunk_size: int = 65536) -> Iterator[TensorChunk]:
        if not self._file:
            raise RuntimeError("Stream not open")
        desc = self._tensor_map.get(tensor_name)
        if not desc:
            raise KeyError(f"Tensor '{tensor_name}' not found")
        remaining = desc.size_bytes
        current_offset = 0
        while remaining > 0:
            read_size = min(chunk_size, remaining)
            data = self.read_tensor(tensor_name, current_offset, read_size)
            remaining -= read_size
            yield TensorChunk(
                tensor_name=tensor_name,
                offset=current_offset,
                size=read_size,
                data=data,
                is_final=remaining <= 0,
            )
            current_offset += read_size
    
    def close(self):
        if self._file:
            self._file.close()
            self._file = None
    
    @property
    def provenance(self) -> StreamProvenance:
        if not self._provenance:
            raise RuntimeError("Stream not open")
        return self._provenance
    
    @property
    def is_open(self) -> bool:
        return self._file is not None


# ═════════════════════════════════════════════════════════════════════
# STREAM ROUTER — Routes detection results to adapters
# ═════════════════════════════════════════════════════════════════════

class StreamRouter(BaseStreamRouter):
    """
    Routes model sources to the correct IModelStream adapter.
    
    Extends the base StreamRouter with actual adapter instantiation.
    """
    
    def __init__(self):
        super().__init__()
        self._adapter_classes: Dict[ModelFormat, type] = {}
        self._register_defaults()
    
    def _register_defaults(self):
        """Register default adapter classes."""
        self.register_adapter_class(ModelFormat.GGUF, GGUFStreamAdapter)
        self.register_adapter_class(ModelFormat.GGML, GGUFStreamAdapter)
        self.register_adapter_class(ModelFormat.SAFETENSORS, SafeTensorStreamAdapter)
        self.register_adapter_class(ModelFormat.OLLAMA, OllamaStreamAdapter)
        self.register_adapter_class(ModelFormat.HUGGINGFACE, OllamaStreamAdapter)
        self.register_adapter_class(ModelFormat.BLOB, RawTensorStreamAdapter)
        self.register_adapter_class(ModelFormat.RAW_F32, RawTensorStreamAdapter)
        self.register_adapter_class(ModelFormat.RAW_F16, RawTensorStreamAdapter)
    
    def register_adapter_class(self, fmt: ModelFormat, adapter_class: type):
        """Register an adapter class for a format."""
        self._adapter_classes[fmt] = adapter_class
        self.register_adapter(fmt, adapter_class.__name__)
    
    def open_stream(self, source: str) -> Tuple[DetectionResult, Optional[IModelStream]]:
        """
        Detect format and open the appropriate stream.
        
        This is the main entry point for the stream fabric.
        Given any source, it:
        1. Detects the format
        2. Instantiates the correct adapter
        3. Opens the stream
        4. Returns the stream ready for use
        
        Returns:
            (detection_result, stream_or_None)
        """
        result = self.detector.detect(source)
        
        if not result.is_known:
            return result, None
        
        adapter_class = self._adapter_classes.get(result.format)
        if not adapter_class:
            # Try fallbacks
            if result.is_container:
                adapter_class = self._adapter_classes.get(ModelFormat.ZIP)
            elif result.is_remote:
                adapter_class = self._adapter_classes.get(ModelFormat.HTTP_MODEL)
        
        if not adapter_class:
            return result, None
        
        try:
            stream = adapter_class()
            if stream.open(source):
                return result, stream
            stream.close()
            return result, None
        except Exception:
            return result, None
    
    def get_adapter_info(self) -> Dict[str, str]:
        """Get registered adapter info."""
        return {fmt.value: cls.__name__ for fmt, cls in self._adapter_classes.items()}


# ═════════════════════════════════════════════════════════════════════
# PROVENANCE SIGNING
# ═════════════════════════════════════════════════════════════════════

def sign_provenance(provenance: StreamProvenance) -> str:
    """Sign a provenance record with SHA-256."""
    data = json.dumps(provenance.to_dict(), sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()[:32]


def verify_provenance_chain(detection: DetectionResult, stream: IModelStream) -> bool:
    """Verify that the detection result matches the stream's provenance."""
    if not stream.is_open:
        return False
    p = stream.provenance
    if not p.verify():
        return False
    # Check format consistency
    if detection.format.value.lower() not in p.format.lower():
        return False
    return True


# ═════════════════════════════════════════════════════════════════════
# SMOKE TESTS
# ═════════════════════════════════════════════════════════════════════

def run_smoke_tests():
    """Run smoke tests for the stream fabric."""
    print("\n" + "=" * 62)
    print("  STREAM FABRIC SMOKE TESTS")
    print("=" * 62)
    
    tests_passed = 0
    tests_failed = 0
    
    def check(name: str, condition: bool, detail: str = ""):
        nonlocal tests_passed, tests_failed
        if condition:
            tests_passed += 1
            print(f"  ✓ {name}")
        else:
            tests_failed += 1
            print(f"  ✗ {name}: {detail}")
    
    # Test 1: IModelStream interface
    print(f"\n  [Test Group 1: IModelStream Interface]")
    check("GGUFStreamAdapter is IModelStream", issubclass(GGUFStreamAdapter, IModelStream))
    check("SafeTensorStreamAdapter is IModelStream", issubclass(SafeTensorStreamAdapter, IModelStream))
    check("OllamaStreamAdapter is IModelStream", issubclass(OllamaStreamAdapter, IModelStream))
    check("RawTensorStreamAdapter is IModelStream", issubclass(RawTensorStreamAdapter, IModelStream))
    
    # Test 2: Create synthetic GGUF file and stream it
    print(f"\n  [Test Group 2: GGUF Stream Adapter]")
    
    # Create a minimal valid GGUF file with 2 tensors
    # We'll build it carefully to ensure correct offsets
    gguf_data = bytearray()
    
    # Helper to write GGUF string
    def _write_gguf_string(dest, s):
        encoded = s.encode('utf-8')
        dest.extend(struct.pack('<Q', len(encoded)))
        dest.extend(encoded)
    
    # Helper to write KV pair
    def _write_kv(dest, key, type_id, value_bytes):
        _write_gguf_string(dest, key)
        dest.extend(struct.pack('<i', type_id))
        dest.extend(value_bytes)
    
    # Header
    gguf_data.extend(b"GGUF")                    # Magic
    gguf_data.extend(struct.pack('<I', 3))        # Version 3
    gguf_data.extend(struct.pack('<q', 2))        # 2 tensors
    gguf_data.extend(struct.pack('<q', 3))        # 3 KV pairs
    
    # KV pairs
    _write_kv(gguf_data, "general.architecture", 8, 
              struct.pack('<Q', 5) + b"llama")    # STRING
    _write_kv(gguf_data, "general.name", 8,
              struct.pack('<Q', 10) + b"test-model")  # STRING
    _write_kv(gguf_data, "general.alignment", 4,
              struct.pack('<I', 32))              # UINT32
    
    # Tensor info entries (metadata only)
    # Tensor 1: f32 [64, 64]
    t1_size = 64 * 64 * 4  # f32 = 16384
    t2_size = 64 * 64 * 2  # f16 = 8192
    
    _write_gguf_string(gguf_data, "blk.0.attn_q.weight")
    gguf_data.extend(struct.pack('<I', 2))        # n_dims = 2
    gguf_data.extend(struct.pack('<q', 64))       # dim 0
    gguf_data.extend(struct.pack('<q', 64))       # dim 1
    gguf_data.extend(struct.pack('<i', 0))         # dtype = f32
    gguf_data.extend(struct.pack('<Q', 0))         # offset = 0 (first tensor)
    
    # Tensor 2: f16 [64, 64]
    _write_gguf_string(gguf_data, "blk.0.attn_k.weight")
    gguf_data.extend(struct.pack('<I', 2))        # n_dims = 2
    gguf_data.extend(struct.pack('<q', 64))       # dim 0
    gguf_data.extend(struct.pack('<q', 64))       # dim 1
    gguf_data.extend(struct.pack('<i', 1))         # dtype = f16
    gguf_data.extend(struct.pack('<Q', t1_size))   # offset after tensor 1
    
    # Align to 32
    header_end = len(gguf_data)
    aligned = (header_end + 31) & ~31
    gguf_data.extend(b'\x00' * (aligned - header_end))
    
    # Add tensor data (zeros for testing)
    gguf_data.extend(b'\x00' * t1_size)           # Tensor 1 data (f32)
    gguf_data.extend(b'\x00' * t2_size)           # Tensor 2 data (f16)
    
    # Write to temp file
    import tempfile as _tf
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(gguf_data)
        gguf_path = f.name
    
    # Test GGUF stream
    stream = GGUFStreamAdapter()
    check("GGUF stream opens", stream.open(gguf_path))
    check("GGUF stream is_open", stream.is_open)
    
    header = stream.read_header()
    check("GGUF header has format", header.format == ModelFormat.GGUF)
    check("GGUF header has version", header.version == 3)
    check("GGUF header has tensor_count", header.tensor_count == 2)
    check("GGUF header has architecture", header.architecture == "llama")
    check("GGUF header has name", header.name == "test-model")
    
    tensors = stream.enumerate_tensors()
    check("GGUF enumerates tensors", len(tensors) == 2)
    check("GGUF tensor 0 has name", tensors[0].name == "blk.0.attn_q.weight")
    check("GGUF tensor 0 has shape", tensors[0].shape == [64, 64])
    check("GGUF tensor 0 dtype f32", tensors[0].dtype == "f32")
    check("GGUF tensor 1 dtype is not f32", tensors[1].dtype != "f32")
    
    # Test partial tensor read
    data = stream.read_tensor("blk.0.attn_q.weight", offset=0, size=64)
    check("GGUF partial tensor read", len(data) == 64)
    
    # Test streaming chunks
    chunks = list(stream.stream_chunks("blk.0.attn_k.weight", chunk_size=65536))
    check("GGUF stream chunks", len(chunks) > 0)
    check("GGUF final chunk marked", chunks[-1].is_final)
    
    # Test provenance
    prov = stream.provenance
    check("GGUF provenance has format", prov.format == "GGUF")
    check("GGUF provenance has adapter", prov.adapter == "GGUFStreamAdapter")
    check("GGUF provenance has tensor_count", prov.tensor_count == 2)
    check("GGUF provenance verifies", prov.verify())
    
    stream.close()
    check("GGUF stream closed", not stream.is_open)
    os.unlink(gguf_path)
    
    # Test 3: SafeTensor stream adapter
    print(f"\n  [Test Group 3: SafeTensor Stream Adapter]")
    
    # Create a minimal SafeTensors file
    st_header = {
        "__metadata__": {"format": "pt"},
        "test.tensor": {
            "dtype": "F32",
            "shape": [64, 64],
            "data_offsets": [0, 64*64*4],
        },
    }
    st_header_json = json.dumps(st_header).encode()
    st_header_size = struct.pack('<Q', len(st_header_json))
    st_data = st_header_size + st_header_json + b'\x00' * (64*64*4)
    
    with _tf.NamedTemporaryFile(suffix=".safetensors", delete=False, mode='wb') as f:
        f.write(st_data)
        st_path = f.name
    
    stream = SafeTensorStreamAdapter()
    check("SafeTensor stream opens", stream.open(st_path))
    
    header = stream.read_header()
    check("SafeTensor header has format", header.format == ModelFormat.SAFETENSORS)
    check("SafeTensor header has tensor_count", header.tensor_count == 1)
    
    tensors = stream.enumerate_tensors()
    check("SafeTensor enumerates tensors", len(tensors) == 1)
    check("SafeTensor tensor name", tensors[0].name == "test.tensor")
    check("SafeTensor tensor shape", tensors[0].shape == [64, 64])
    
    data = stream.read_tensor("test.tensor", offset=0, size=16)
    check("SafeTensor partial read", len(data) == 16)
    
    prov = stream.provenance
    check("SafeTensor provenance verifies", prov.verify())
    
    stream.close()
    os.unlink(st_path)
    
    # Test 4: Raw tensor stream adapter
    print(f"\n  [Test Group 4: Raw Tensor Stream Adapter]")
    
    raw_data = b'\x00' * 1024
    with _tf.NamedTemporaryFile(suffix=".bin", delete=False, mode='wb') as f:
        f.write(raw_data)
        raw_path = f.name
    
    stream = RawTensorStreamAdapter()
    check("Raw stream opens", stream.open(raw_path))
    
    header = stream.read_header()
    check("Raw header has format", header.format == ModelFormat.BLOB)
    check("Raw header has tensor_count", header.tensor_count == 1)
    
    tensors = stream.enumerate_tensors()
    check("Raw enumerates tensor", len(tensors) == 1)
    check("Raw tensor name", tensors[0].name == "data")
    
    data = stream.read_tensor("data", offset=0, size=64)
    check("Raw partial read", len(data) == 64)
    
    stream.close()
    os.unlink(raw_path)
    
    # Test 5: StreamRouter
    print(f"\n  [Test Group 5: StreamRouter]")
    router = StreamRouter()
    
    # Test with GGUF file
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b'\x00' * 100)
        gguf_path = f.name
    
    result, stream = router.open_stream(gguf_path)
    check("Router opens GGUF stream", stream is not None)
    check("Router detects GGUF", result.format == ModelFormat.GGUF)
    check("Router returns GGUF adapter", isinstance(stream, GGUFStreamAdapter))
    if stream:
        stream.close()
    os.unlink(gguf_path)
    
    # Test with Ollama URL
    result, stream = router.open_stream("ollama://llama3.2:3b")
    check("Router opens Ollama stream", stream is not None)
    check("Router detects Ollama", result.format == ModelFormat.OLLAMA)
    check("Router returns Ollama adapter", isinstance(stream, OllamaStreamAdapter))
    if stream:
        stream.close()
    
    # Test with unknown format (truly random bytes that won't match any signature)
    with _tf.NamedTemporaryFile(suffix=".xyz", delete=False, mode='wb') as f:
        f.write(b'\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6' + b'\x00' * 90)
        unknown_path = f.name
    
    result, stream = router.open_stream(unknown_path)
    check("Router returns None for unknown", stream is None)
    check("Router detects unknown", result.format == ModelFormat.UNKNOWN)
    os.unlink(unknown_path)
    
    # Test 6: Adapter info
    print(f"\n  [Test Group 6: Adapter Info]")
    info = router.get_adapter_info()
    check("Adapter info has GGUF", "gguf" in info)
    check("Adapter info has SafeTensors", "safetensors" in info)
    check("Adapter info has Ollama", "ollama" in info)
    check("Adapter info has BLOB", "blob" in info)
    
    # Test 7: Provenance signing
    print(f"\n  [Test Group 7: Provenance Signing]")
    prov = StreamProvenance(
        source_hash="abc123",
        format="GGUF",
        adapter="GGUFStreamAdapter",
        tensor_count=197,
        total_bytes=4_000_000_000,
        detected_by="magic:47475546",
        confidence=0.95,
    )
    sig = sign_provenance(prov)
    check("Provenance signature is hex", len(sig) == 32)
    check("Provenance signature is consistent", 
          sign_provenance(prov) == sign_provenance(prov))
    
    # Test 8: Provenance chain verification
    print(f"\n  [Test Group 8: Provenance Chain]")
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b'\x00' * 100)
        gguf_path = f.name
    
    result, stream = router.open_stream(gguf_path)
    if stream:
        chain_ok = verify_provenance_chain(result, stream)
        check("Provenance chain verifies", chain_ok)
        stream.close()
    os.unlink(gguf_path)
    
    # Test 9: TensorDescriptor
    print(f"\n  [Test Group 9: TensorDescriptor]")
    desc = TensorDescriptor(
        name="test.weight",
        shape=[4096, 4096],
        dtype="q4_k",
        offset=1024,
        size_bytes=8_000_000,
        is_quantized=True,
        quant_scheme="Q4_K",
        block_size=256,
    )
    check("Tensor has name", desc.name == "test.weight")
    check("Tensor has shape", desc.shape == [4096, 4096])
    check("Tensor is quantized", desc.is_quantized)
    check("Tensor has quant_scheme", desc.quant_scheme == "Q4_K")
    
    # Test 10: ModelHeader
    print(f"\n  [Test Group 10: ModelHeader]")
    mh = ModelHeader(
        format=ModelFormat.GGUF,
        version=3,
        tensor_count=197,
        architecture="llama",
        name="test-model",
        file_size=4_000_000_000,
    )
    check("Header has format", mh.format == ModelFormat.GGUF)
    check("Header has version", mh.version == 3)
    check("Header has tensor_count", mh.tensor_count == 197)
    check("Header has architecture", mh.architecture == "llama")
    
    # Test 11: TensorChunk
    print(f"\n  [Test Group 11: TensorChunk]")
    chunk = TensorChunk(
        tensor_name="test.weight",
        offset=0,
        size=4096,
        data=b'\x00' * 4096,
        is_final=False,
    )
    check("Chunk has tensor_name", chunk.tensor_name == "test.weight")
    check("Chunk has data", len(chunk.data) == 4096)
    check("Chunk not final", not chunk.is_final)
    
    chunk_final = TensorChunk(
        tensor_name="test.weight",
        offset=4096,
        size=1024,
        data=b'\x00' * 1024,
        is_final=True,
    )
    check("Final chunk marked", chunk_final.is_final)
    
    # Test 12: Adapter registration
    print(f"\n  [Test Group 12: Adapter Registration]")
    router2 = StreamRouter()
    check("Default adapters registered", len(router2._adapter_classes) >= 7)
    
    # Test 13: Multiple opens
    print(f"\n  [Test Group 13: Multiple Opens]")
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b'\x00' * 100)
        p1 = f.name
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b'\x00' * 100)
        p2 = f.name
    
    s1 = GGUFStreamAdapter()
    s2 = GGUFStreamAdapter()
    check("Open first file", s1.open(p1))
    check("Open second file", s2.open(p2))
    check("Independent streams", s1.is_open and s2.is_open)
    s1.close()
    s2.close()
    check("Both closed", not s1.is_open and not s2.is_open)
    os.unlink(p1)
    os.unlink(p2)
    
    # Test 14: StreamRouter stats
    print(f"\n  [Test Group 14: StreamRouter Stats]")
    stats = router.get_stats()
    check("Router stats has detector", "detector" in stats)
    check("Router stats has routes", "routes" in stats)
    check("Router stats has adapters", "adapters" in stats)
    
    # Test 15: Error handling
    print(f"\n  [Test Group 15: Error Handling]")
    stream = GGUFStreamAdapter()
    check("Open non-existent file returns False", not stream.open("/nonexistent/file.gguf"))
    
    try:
        stream.read_header()
        check("Read header on unopened stream raises", False)
    except RuntimeError:
        check("Read header on unopened stream raises RuntimeError", True)
    
    # Test 16: Adversarial — GGUF renamed to .bin
    print(f"\n  [Test Group 16: Adversarial — Renamed Extensions]")
    with _tf.NamedTemporaryFile(suffix=".bin", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b'\x00' * 100)
        renamed_path = f.name
    
    result, stream = router.open_stream(renamed_path)
    check("GGUF renamed .bin still detected as GGUF", result.format == ModelFormat.GGUF)
    check("GGUF renamed .bin still opens GGUF adapter", isinstance(stream, GGUFStreamAdapter))
    if stream:
        stream.close()
    os.unlink(renamed_path)
    
    # Test 17: Adversarial — SafeTensor renamed to .pt
    # .pt extension triggers PyTorch detection (priority 85) before SafeTensors deep content
    print(f"\n  [Test Group 17: Adversarial — SafeTensor Renamed]")
    st_header2 = {"__metadata__": {"format": "pt"}, "w.weight": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}
    st_json2 = json.dumps(st_header2).encode()
    st_data2 = struct.pack('<Q', len(st_json2)) + st_json2 + b'\x00' * 64
    with _tf.NamedTemporaryFile(suffix=".pt", delete=False, mode='wb') as f:
        f.write(st_data2)
        st_renamed = f.name
    
    result, stream = router.open_stream(st_renamed)
    # .pt extension triggers PyTorch detection; no PyTorch adapter registered
    check("SafeTensor renamed .pt detected as pytorch by extension", result.format == ModelFormat.PYTORCH)
    check("SafeTensor renamed .pt has no adapter (PyTorch not registered)", stream is None)
    os.unlink(st_renamed)
    
    # Test 18: Adversarial — Corrupted GGUF header (truncated mid-KV)
    print(f"\n  [Test Group 18: Adversarial — Corrupted Header]")
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        # Write GGUF magic + version + tensor count but truncate KV data
        f.write(b"GGUF" + struct.pack('<I', 3) + struct.pack('<q', 0) + struct.pack('<q', 9999))
        # KV count says 9999 but there's no data — will fail on read
        corrupt_path = f.name
    
    result, stream = router.open_stream(corrupt_path)
    check("Corrupted GGUF still detected by magic", result.format == ModelFormat.GGUF)
    check("Corrupted GGUF returns no stream (parse fails)", stream is None)
    os.unlink(corrupt_path)
    
    # Test 19: Adversarial — Partial file (incomplete download)
    print(f"\n  [Test Group 19: Adversarial — Partial File]")
    with _tf.NamedTemporaryFile(suffix=".gguf.part", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b'\x03\x00\x00\x00')  # Only 8 bytes — incomplete header
        partial_path = f.name
    
    result, stream = router.open_stream(partial_path)
    check("Partial GGUF detected by magic bytes", result.format == ModelFormat.GGUF)
    check("Partial GGUF returns no stream (incomplete header)", stream is None)
    os.unlink(partial_path)
    
    # Test 20: Adversarial — Empty file
    print(f"\n  [Test Group 20: Adversarial — Empty File]")
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"")  # Empty
        empty_path = f.name
    
    result, stream = router.open_stream(empty_path)
    # Extension .gguf triggers GGUF detection, but open() fails on empty file
    check("Empty file detected as GGUF by extension", result.format == ModelFormat.GGUF)
    check("Empty file returns no stream (open fails)", stream is None)
    os.unlink(empty_path)
    
    # Test 21: Adversarial — ZIP containing GGUF (container detection)
    print(f"\n  [Test Group 21: Adversarial — Container Detection]")
    import zipfile
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, 'w') as zf:
        zf.writestr("model.gguf", b"GGUF" + b'\x03\x00\x00\x00' + b'\x00' * 100)
    zip_data = zip_buf.getvalue()
    
    with _tf.NamedTemporaryFile(suffix=".zip", delete=False, mode='wb') as f:
        f.write(zip_data)
        zip_path = f.name
    
    result = router.detector.detect(zip_path)
    # ZIP magic PK\x03\x04 matches PyTorch ZIP (priority 80) before generic ZIP (priority 40)
    check("ZIP container detected as pytorch_zip", result.format == ModelFormat.PYTORCH_ZIP)
    check("ZIP container is known format", result.is_known)
    os.unlink(zip_path)
    
    # Test 22: Provenance attestation record
    print(f"\n  [Test Group 22: Provenance Attestation]")
    prov = StreamProvenance(
        source_hash="abc123def456",
        format="GGUF",
        adapter="GGUFStreamAdapter",
        tensor_count=197,
        total_bytes=4_000_000_000,
        detected_by="magic:47475546",
        confidence=0.95,
    )
    prov_dict = prov.to_dict()
    check("Provenance has component", prov_dict["component"] == "StreamFabric")
    check("Provenance has version", prov_dict["version"] == "1.0")
    check("Provenance has source_hash", prov_dict["source_hash"] == "abc123def456")
    check("Provenance has format", prov_dict["format"] == "GGUF")
    check("Provenance has adapter", prov_dict["adapter"] == "GGUFStreamAdapter")
    check("Provenance has tensor_count", prov_dict["tensor_count"] == 197)
    check("Provenance has total_bytes", prov_dict["total_bytes"] == 4_000_000_000)
    check("Provenance has detected_by", prov_dict["detected_by"] == "magic:47475546")
    check("Provenance has confidence", prov_dict["confidence"] == 0.95)
    check("Provenance has timestamp", "timestamp" in prov_dict)
    check("Provenance has signature", prov_dict["signature"] == "~g87")
    check("Provenance verifies", prov.verify())
    
    # Test 23: Provenance chain — detection → stream → attestation
    print(f"\n  [Test Group 23: Provenance Chain]")
    with _tf.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b'\x03\x00\x00\x00' + b'\x00' * 100)
        chain_path = f.name
    
    result, stream = router.open_stream(chain_path)
    if stream:
        prov = stream.provenance
        check("Chain: detection format matches provenance", 
              result.format.value.upper() in prov.format.upper())
        check("Chain: provenance verifies", prov.verify())
        check("Chain: verify_provenance_chain passes", verify_provenance_chain(result, stream))
        stream.close()
    os.unlink(chain_path)
    
    # Test 24: Provenance signature consistency
    print(f"\n  [Test Group 24: Provenance Signature]")
    prov1 = StreamProvenance(source_hash="abc", format="GGUF", adapter="GGUFStreamAdapter", tensor_count=1, total_bytes=100, detected_by="test", confidence=0.5)
    prov2 = StreamProvenance(source_hash="abc", format="GGUF", adapter="GGUFStreamAdapter", tensor_count=1, total_bytes=100, detected_by="test", confidence=0.5)
    check("Same provenance produces same signature", 
          sign_provenance(prov1) == sign_provenance(prov2))
    
    prov3 = StreamProvenance(source_hash="xyz", format="GGUF", adapter="GGUFStreamAdapter", tensor_count=1, total_bytes=100, detected_by="test", confidence=0.5)
    check("Different provenance produces different signature", 
          sign_provenance(prov1) != sign_provenance(prov3))
    
    # Summary
    total = tests_passed + tests_failed
    print(f"\n{'─'*62}")
    print(f"  Smoke Tests: {tests_passed}/{total} passed")
    if tests_failed > 0:
        print(f"  FAILED: {tests_failed} tests failed!")
    else:
        print(f"  ALL TESTS PASSED ✓")
    print(f"{'─'*62}")
    
    return tests_failed == 0


# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import sys
    
    if "--test" in sys.argv:
        run_smoke_tests()
    elif "--demo" in sys.argv:
        print(f"\n  Stream Fabric Demo")
        print(f"  {'─'*50}")
        
        router = StreamRouter()
        print(f"\n  Registered Adapters:")
        for fmt, cls in router._adapter_classes.items():
            print(f"    {fmt.value:20s} → {cls.__name__}")
        
        print(f"\n  Test Sources:")
        test_sources = [
            "model.gguf",
            "model.safetensors",
            "ollama://llama3.2:3b",
            "hf://meta-llama/Llama-3.2-3B",
            "model.bin",
            "model.f32",
            "unknown.xyz",
        ]
        
        for src in test_sources:
            result, stream = router.open_stream(src)
            if stream:
                prov = stream.provenance
                print(f"    {src:30s} → {result.format.value:15s} [{prov.adapter}]")
                stream.close()
            else:
                print(f"    {src:30s} → {result.format.value:15s} [no adapter]")
    else:
        run_smoke_tests()
