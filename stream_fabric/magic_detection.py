"""
Magic Detection Engine — Reverse Engineered Format Sniffing

Detects model file formats by reading their magic bytes/headers.
Supports ALL known ML model formats plus generic fallback detection.

Each format has a unique "fingerprint" — the first few bytes of the file.
This engine reads those bytes and identifies the format instantly.

Signed: ~g87 | RawrXD | uwu kawaii
"""

import struct
import gzip
import zlib
import json
import os
import re
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum, auto
from pathlib import Path


# ═════════════════════════════════════════════════════════════════════
# FORMAT ENUMERATION — Every format we can detect
# ═════════════════════════════════════════════════════════════════════

class ModelFormat(Enum):
    """All detectable model file formats."""
    # GGML family
    GGUF = "gguf"                    # GGUF (GGML Universal Format) v1-v3
    GGML = "ggml"                    # Legacy GGML format
    GGML_V2 = "ggml_v2"              # GGML v2 (older)
    
    # SafeTensors
    SAFETENSORS = "safetensors"      # Hugging Face SafeTensors
    
    # PyTorch
    PYTORCH = "pytorch"              # PyTorch .pt/.pth
    PYTORCH_ZIP = "pytorch_zip"      # PyTorch zip-based (JIT)
    
    # Hugging Face
    HF_BIN = "hf_bin"                # Hugging Face .bin
    HF_MODEL = "hf_model"            # Hugging Face model index
    
    # ONNX
    ONNX = "onnx"                    # Open Neural Network Exchange
    
    # TensorFlow
    TENSORFLOW = "tensorflow"        # TF SavedModel / checkpoint
    TFLITE = "tflite"                # TensorFlow Lite
    
    # Keras
    KERAS_H5 = "keras_h5"            # Keras HDF5 (.h5)
    KERAS_V3 = "keras_v3"            # Keras v3 (.keras)
    
    # JAX / Flax
    FLAX = "flax"                    # Flax checkpoint
    JAX = "jax"                      # JAX serialized
    
    # Apple
    COREML = "coreml"                # Apple CoreML (.mlmodel/.mlpackage)
    
    # OpenVINO
    OPENVINO = "openvino"            # Intel OpenVINO IR (.xml + .bin)
    
    # GGML variants
    GGML_Q4_0 = "ggml_q4_0"          # GGML Q4_0 quantized
    GGML_Q4_1 = "ggml_q4_1"          # GGML Q4_1 quantized
    GGML_Q5_0 = "ggml_q5_0"          # GGML Q5_0 quantized
    GGML_Q5_1 = "ggml_q5_1"          # GGML Q5_1 quantized
    GGML_Q8_0 = "ggml_q8_0"          # GGML Q8_0 quantized
    
    # AWQ
    AWQ = "awq"                      # Activation-aware Weight Quantization
    
    # GPTQ
    GPTQ = "gptq"                    # GPTQ quantized
    
    # EXL2
    EXL2 = "exl2"                    # ExLlama v2 format
    
    # BLOB / Raw
    BLOB = "blob"                    # Raw binary tensor blob
    RAW_F16 = "raw_f16"              # Raw FP16 tensor data
    RAW_F32 = "raw_f32"              # Raw FP32 tensor data
    
    # Remote / API
    OLLAMA = "ollama"                # Ollama API model reference
    HUGGINGFACE = "huggingface"      # Hugging Face Hub reference
    HTTP_MODEL = "http_model"        # Generic HTTP model endpoint
    
    # Container formats
    TAR = "tar"                      # Tarball
    ZIP = "zip"                      # Zip archive
    TARGZ = "targz"                  # Gzipped tarball
    
    # Config / Metadata
    JSON_CONFIG = "json_config"      # JSON model config
    YAML_CONFIG = "yaml_config"      # YAML model config
    TOML_CONFIG = "toml_config"      # TOML model config
    
    # Unknown
    UNKNOWN = "unknown"              # Could not identify


# ═════════════════════════════════════════════════════════════════════
# MAGIC BYTE DATABASE — Every format's unique fingerprint
# ═════════════════════════════════════════════════════════════════════

@dataclass
class MagicSignature:
    """A single magic byte signature for a format."""
    format: ModelFormat
    magic: bytes                      # The magic bytes to match
    offset: int = 0                   # Offset in file to check
    mask: Optional[bytes] = None      # Optional mask (for fuzzy matching)
    description: str = ""
    priority: int = 0                # Higher = checked first
    min_file_size: int = 4           # Minimum file size to check
    extensions: List[str] = field(default_factory=list)


# The master magic byte database
# Each entry: (format, magic_bytes, offset, description, priority, extensions)
MAGIC_DATABASE: List[MagicSignature] = [
    # ── GGML Family ────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.GGUF,
        magic=b"GGUF",
        offset=0,
        description="GGUF v1/v2/v3 — GGML Universal Format",
        priority=100,
        extensions=[".gguf"],
    ),
    MagicSignature(
        format=ModelFormat.GGML,
        magic=b"ggml",
        offset=0,
        description="Legacy GGML format",
        priority=90,
        extensions=[".ggml"],
    ),
    MagicSignature(
        format=ModelFormat.GGML_Q4_0,
        magic=b"\x00\x00\x00\x00",  # GGML Q4_0 has specific header
        offset=0,
        description="GGML Q4_0 quantized",
        priority=50,
        extensions=[".ggml"],
    ),
    
    # ── SafeTensors ────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.SAFETENSORS,
        magic=b"\x00\x00\x00\x00\x00\x00\x00\x00",  # 8 zero bytes header
        offset=0,
        description="Hugging Face SafeTensors — zero-header prefix",
        priority=95,
        extensions=[".safetensors"],
    ),
    
    # ── PyTorch ────────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.PYTORCH,
        magic=b"\x80\x02",  # pickle protocol 2
        offset=0,
        description="PyTorch .pt/.pth (pickle format)",
        priority=85,
        extensions=[".pt", ".pth"],
    ),
    MagicSignature(
        format=ModelFormat.PYTORCH_ZIP,
        magic=b"PK\x03\x04",  # ZIP header (PyTorch JIT)
        offset=0,
        description="PyTorch JIT script (zip-based)",
        priority=80,
        extensions=[".pt", ".pth"],
    ),
    
    # ── ONNX ───────────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.ONNX,
        magic=b"\x08\x00\x00\x00",  # ONNX protobuf header
        offset=0,
        description="ONNX model (protobuf format)",
        priority=90,
        extensions=[".onnx"],
    ),
    MagicSignature(
        format=ModelFormat.ONNX,
        magic=b"\x08\x08",  # ONNX v8
        offset=0,
        description="ONNX v8 model",
        priority=85,
        extensions=[".onnx"],
    ),
    
    # ── TensorFlow ─────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.TENSORFLOW,
        magic=b"\x08\x01",  # TF checkpoint header
        offset=0,
        description="TensorFlow checkpoint",
        priority=70,
        extensions=[".ckpt", ".ckpt.index", ".ckpt.data"],
    ),
    MagicSignature(
        format=ModelFormat.TFLITE,
        magic=b"TFL3",  # TensorFlow Lite v3
        offset=0,
        description="TensorFlow Lite model",
        priority=80,
        extensions=[".tflite"],
    ),
    
    # ── Keras ──────────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.KERAS_H5,
        magic=b"\x89HDF\r\n\x1a\n",  # HDF5 format
        offset=0,
        description="Keras HDF5 model (.h5)",
        priority=75,
        extensions=[".h5", ".hdf5", ".keras"],
    ),
    
    # ── CoreML ─────────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.COREML,
        magic=b"\x1f\x8b\x08",  # GZIP (CoreML .mlmodel is gzipped protobuf)
        offset=0,
        description="Apple CoreML model (gzipped protobuf)",
        priority=60,
        extensions=[".mlmodel"],
    ),
    
    # ── AWQ ─────────────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.AWQ,
        magic=b"AWQ\x00",  # AWQ format marker
        offset=0,
        description="Activation-aware Weight Quantization",
        priority=70,
        extensions=[".awq"],
    ),
    
    # ── EXL2 ───────────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.EXL2,
        magic=b"EXL2",  # ExLlama v2 format
        offset=0,
        description="ExLlama v2 quantized format",
        priority=70,
        extensions=[".exl2"],
    ),
    
    # ── Container Formats ─────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.ZIP,
        magic=b"PK\x03\x04",
        offset=0,
        description="ZIP archive",
        priority=40,
        extensions=[".zip"],
    ),
    MagicSignature(
        format=ModelFormat.TAR,
        magic=b"ustar\x00",  # POSIX tar
        offset=257,           # Tar header has magic at offset 257
        description="TAR archive",
        priority=40,
        extensions=[".tar"],
    ),
    MagicSignature(
        format=ModelFormat.TARGZ,
        magic=b"\x1f\x8b\x08",
        offset=0,
        description="Gzipped file (may be tarball)",
        priority=40,
        extensions=[".tgz", ".tar.gz"],
    ),
    
    # ── JSON Config ────────────────────────────────────────────────
    MagicSignature(
        format=ModelFormat.JSON_CONFIG,
        magic=b"{",
        offset=0,
        description="JSON file (model config)",
        priority=30,
        extensions=[".json"],
    ),
    MagicSignature(
        format=ModelFormat.JSON_CONFIG,
        magic=b"[",
        offset=0,
        description="JSON array file",
        priority=25,
        extensions=[".json"],
    ),
]


# ═════════════════════════════════════════════════════════════════════
# EXTENSION-BASED FALLBACK DETECTION
# ═════════════════════════════════════════════════════════════════════

# When magic bytes don't match, fall back to extension matching
EXTENSION_MAP: Dict[str, ModelFormat] = {
    # GGML family
    ".gguf": ModelFormat.GGUF,
    ".ggml": ModelFormat.GGML,
    
    # SafeTensors
    ".safetensors": ModelFormat.SAFETENSORS,
    
    # PyTorch
    ".pt": ModelFormat.PYTORCH,
    ".pth": ModelFormat.PYTORCH,
    ".pt2": ModelFormat.PYTORCH,
    
    # ONNX
    ".onnx": ModelFormat.ONNX,
    
    # TensorFlow
    ".tflite": ModelFormat.TFLITE,
    ".pb": ModelFormat.TENSORFLOW,
    ".ckpt": ModelFormat.TENSORFLOW,
    ".ckpt.index": ModelFormat.TENSORFLOW,
    ".ckpt.data": ModelFormat.TENSORFLOW,
    ".saved_model": ModelFormat.TENSORFLOW,
    
    # Keras
    ".h5": ModelFormat.KERAS_H5,
    ".hdf5": ModelFormat.KERAS_H5,
    ".keras": ModelFormat.KERAS_V3,
    
    # Apple
    ".mlmodel": ModelFormat.COREML,
    ".mlpackage": ModelFormat.COREML,
    
    # OpenVINO
    ".xml": ModelFormat.OPENVINO,
    ".bin": ModelFormat.BLOB,
    
    # Quantized
    ".awq": ModelFormat.AWQ,
    ".gptq": ModelFormat.GPTQ,
    ".exl2": ModelFormat.EXL2,
    
    # Raw
    ".f16": ModelFormat.RAW_F16,
    ".fp16": ModelFormat.RAW_F16,
    ".f32": ModelFormat.RAW_F32,
    ".fp32": ModelFormat.RAW_F32,
    ".blob": ModelFormat.BLOB,
    
    # Config
    ".json": ModelFormat.JSON_CONFIG,
    ".yaml": ModelFormat.YAML_CONFIG,
    ".yml": ModelFormat.YAML_CONFIG,
    ".toml": ModelFormat.TOML_CONFIG,
    
    # Archives
    ".zip": ModelFormat.ZIP,
    ".tar": ModelFormat.TAR,
    ".tgz": ModelFormat.TARGZ,
    ".gz": ModelFormat.TARGZ,
}


# ═════════════════════════════════════════════════════════════════════
# CONTENT-BASED DEEP DETECTION
# ═════════════════════════════════════════════════════════════════════

def _detect_by_content(data: bytes, file_path: str) -> Optional[ModelFormat]:
    """
    Deep content inspection for formats that don't have simple magic bytes.
    Reads more of the file to identify the format.
    """
    # ── SafeTensors deep check ─────────────────────────────────────
    # SafeTensors: first 8 bytes are the header size (uint64 little-endian)
    # followed by JSON header. The 8 zero bytes are the size of the header
    # when the header is empty, but normally it's non-zero.
    if len(data) >= 8:
        header_size = struct.unpack('<Q', data[:8])[0]
        if header_size > 0 and header_size < 10 * 1024 * 1024:  # Sanity: < 10MB
            # Check if the header is valid JSON
            if len(data) >= 8 + header_size:
                try:
                    header_json = json.loads(data[8:8 + header_size])
                    if isinstance(header_json, dict) and "__metadata__" in header_json:
                        return ModelFormat.SAFETENSORS
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
    
    # ── GGUF deep check ───────────────────────────────────────────
    # GGUF: "GGUF" magic at offset 0, followed by version (uint32)
    if data[:4] == b"GGUF":
        return ModelFormat.GGUF
    
    # ── GGML deep check ────────────────────────────────────────────
    if data[:4] == b"ggml":
        return ModelFormat.GGML
    
    # ── ONNX deep check ───────────────────────────────────────────
    # ONNX uses protobuf. Check for the protobuf wire format marker.
    if len(data) >= 4 and data[0] == 0x08 and data[1] in (0x00, 0x01, 0x08):
        # Check for ONNX model identifier
        try:
            text = data[:100].decode('latin-1')
            if 'ir_version' in text or 'producer_name' in text or 'opset_import' in text:
                return ModelFormat.ONNX
        except:
            pass
    
    # ── PyTorch deep check ────────────────────────────────────────
    # PyTorch uses pickle. Check for pickle protocol markers.
    if len(data) >= 4:
        # pickle protocol 2: \x80\x02
        if data[:2] == b'\x80\x02':
            return ModelFormat.PYTORCH
        # pickle protocol 3: \x80\x03
        if data[:2] == b'\x80\x03':
            return ModelFormat.PYTORCH
        # pickle protocol 4: \x80\x04
        if data[:2] == b'\x80\x04':
            return ModelFormat.PYTORCH
        # pickle protocol 5: \x80\x05
        if data[:2] == b'\x80\x05':
            return ModelFormat.PYTORCH
    
    # ── HDF5 deep check ───────────────────────────────────────────
    if data[:8] == b'\x89HDF\r\n\x1a\n':
        return ModelFormat.KERAS_H5
    
    # ── GZIP deep check ───────────────────────────────────────────
    if data[:2] == b'\x1f\x8b':
        # Could be CoreML, tarball, or generic gzip
        # Try to decompress and check contents
        try:
            decompressed = gzip.decompress(data[:4096])
            if decompressed[:4] == b'\x0a\x05\x01\x00':  # CoreML protobuf
                return ModelFormat.COREML
            if decompressed[257:262] == b'ustar':  # Tar inside gzip
                return ModelFormat.TARGZ
            # Check for protobuf model inside
            try:
                text = decompressed[:200].decode('latin-1')
                if 'mlmodel' in text or 'specificationVersion' in text:
                    return ModelFormat.COREML
            except:
                pass
        except:
            pass
        return ModelFormat.TARGZ  # Generic gzip
    
    # ── ZIP deep check ────────────────────────────────────────────
    if data[:2] == b'PK':
        # Could be PyTorch JIT or regular zip
        try:
            import zipfile
            import io
            with zipfile.ZipFile(io.BytesIO(data[:4096])) as zf:
                names = zf.namelist()
                if any('data.pkl' in n for n in names):
                    return ModelFormat.PYTORCH_ZIP
                if any('model.pt' in n for n in names):
                    return ModelFormat.PYTORCH_ZIP
                if any('model.safetensors' in n for n in names):
                    return ModelFormat.SAFETENSORS
                if any('model.h5' in n for n in names):
                    return ModelFormat.KERAS_H5
        except:
            pass
        return ModelFormat.ZIP
    
    # ── JSON deep check ───────────────────────────────────────────
    if data[:1] in (b'{', b'['):
        try:
            obj = json.loads(data[:4096].decode('utf-8'))
            if isinstance(obj, dict):
                # Check for model config patterns
                if any(k in obj for k in ['model_type', 'architectures', 'config']):
                    return ModelFormat.JSON_CONFIG
                if 'model_type' in obj:
                    return ModelFormat.JSON_CONFIG
                if 'architectures' in obj:
                    return ModelFormat.JSON_CONFIG
                # Check for Hugging Face model index
                if 'modelIndex' in obj or 'model_id' in obj:
                    return ModelFormat.HF_MODEL
                # Check for Ollama manifest
                if 'model' in obj and 'digest' in obj:
                    return ModelFormat.OLLAMA
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    
    # ── AWQ deep check ───────────────────────────────────────────
    if len(data) >= 8 and data[:4] == b'AWQ\x00':
        return ModelFormat.AWQ
    
    # ── EXL2 deep check ───────────────────────────────────────────
    if len(data) >= 8 and data[:4] == b'EXL2':
        return ModelFormat.EXL2
    
    # ── TFLite deep check ─────────────────────────────────────────
    if len(data) >= 8 and data[:4] in (b'TFL3', b'TFL2', b'TFL1'):
        return ModelFormat.TFLITE
    
    # ── Raw float data detection ─────────────────────────────────
    if len(data) >= 16:
        # Check if it looks like raw FP32 data
        # FP32: check if values are reasonable floats
        try:
            floats = struct.unpack('<4f', data[:16])
            if all(not math.isnan(f) and not math.isinf(f) for f in floats):
                # Could be raw FP32 — check extension
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ('.f32', '.fp32', '.bin', '.blob'):
                    return ModelFormat.RAW_F32
                if ext in ('.f16', '.fp16'):
                    return ModelFormat.RAW_F16
        except:
            pass
    
    return None


# ═════════════════════════════════════════════════════════════════════
# MAGIC DETECTION ENGINE
# ═════════════════════════════════════════════════════════════════════

@dataclass
class DetectionResult:
    """Result of format detection."""
    format: ModelFormat
    confidence: float                # 0.0 - 1.0
    method: str                      # "magic", "extension", "content", "remote"
    detected_by: str                 # Which signature matched
    file_size: int = 0
    header_bytes: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_known(self) -> bool:
        return self.format != ModelFormat.UNKNOWN
    
    @property
    def is_quantized(self) -> bool:
        return self.format in (
            ModelFormat.GGUF, ModelFormat.GGML,
            ModelFormat.GGML_Q4_0, ModelFormat.GGML_Q4_1,
            ModelFormat.GGML_Q5_0, ModelFormat.GGML_Q5_1,
            ModelFormat.GGML_Q8_0,
            ModelFormat.AWQ, ModelFormat.GPTQ, ModelFormat.EXL2,
        )
    
    @property
    def is_remote(self) -> bool:
        return self.format in (
            ModelFormat.OLLAMA, ModelFormat.HUGGINGFACE,
            ModelFormat.HTTP_MODEL,
        )
    
    @property
    def is_container(self) -> bool:
        return self.format in (
            ModelFormat.ZIP, ModelFormat.TAR, ModelFormat.TARGZ,
        )


class MagicDetector:
    """
    The Magic Detection Engine.
    
    Detects model file formats by:
    1. Magic bytes (fastest, most reliable)
    2. File extension (fallback)
    3. Deep content inspection (for ambiguous formats)
    4. Remote URL pattern matching (for API-based models)
    
    Usage:
        detector = MagicDetector()
        result = detector.detect("model.gguf")
        result.format  # ModelFormat.GGUF
        result.confidence  # 1.0
    """
    
    def __init__(self):
        self._cache: Dict[str, DetectionResult] = {}
        self._stats = {
            "detections": 0,
            "cache_hits": 0,
            "by_format": {},
            "by_method": {},
        }
    
    def detect(self, source: str, data: Optional[bytes] = None) -> DetectionResult:
        """
        Detect the format of a model file or source.
        
        Args:
            source: File path, URL, or model identifier
            data: Optional pre-read bytes (if not provided, reads from file)
        
        Returns:
            DetectionResult with format and confidence
        """
        # Check cache
        if source in self._cache:
            self._stats["cache_hits"] += 1
            return self._cache[source]
        
        self._stats["detections"] += 1
        
        # Determine if this is a remote source
        if source.startswith(("http://", "https://", "ollama://", "hf://")):
            result = self._detect_remote(source)
            self._cache[source] = result
            return result
        
        # It's a local file
        file_path = Path(source)
        if not file_path.exists():
            return DetectionResult(
                format=ModelFormat.UNKNOWN,
                confidence=0.0,
                method="none",
                detected_by="file_not_found",
            )
        
        file_size = file_path.stat().st_size
        
        # Read header bytes if not provided
        if data is None:
            try:
                with open(file_path, "rb") as f:
                    data = f.read(4096)  # Read first 4KB for deep detection
            except (IOError, PermissionError):
                return DetectionResult(
                    format=ModelFormat.UNKNOWN,
                    confidence=0.0,
                    method="none",
                    detected_by="read_error",
                    file_size=file_size,
                )
        
        # Step 1: Magic byte detection (fastest, most reliable)
        result = self._detect_by_magic(data, file_path, file_size)
        if result and result.confidence >= 0.9:
            self._cache_result(source, result)
            return result
        
        # Step 2: Extension-based detection (fallback)
        result = self._detect_by_extension(file_path, file_size)
        if result:
            self._cache_result(source, result)
            return result
        
        # Step 3: Deep content inspection (for ambiguous formats)
        result = self._detect_by_content_deep(data, file_path, file_size)
        if result:
            self._cache_result(source, result)
            return result
        
        # Step 4: Unknown
        result = DetectionResult(
            format=ModelFormat.UNKNOWN,
            confidence=0.0,
            method="none",
            detected_by="no_match",
            file_size=file_size,
            header_bytes=data[:32],
        )
        self._cache_result(source, result)
        return result
    
    def _detect_by_magic(self, data: bytes, file_path: Path,
                         file_size: int) -> Optional[DetectionResult]:
        """Step 1: Match magic bytes against the database."""
        if len(data) < 4:
            return None
        
        # Sort by priority (highest first)
        for sig in sorted(MAGIC_DATABASE, key=lambda s: -s.priority):
            if file_size < sig.min_file_size:
                continue
            
            # Check if data is long enough
            check_len = len(sig.magic)
            if len(data) < sig.offset + check_len:
                continue
            
            # Check magic bytes
            chunk = data[sig.offset:sig.offset + check_len]
            
            if sig.mask:
                # Masked comparison
                masked_chunk = bytes(a & b for a, b in zip(chunk, sig.mask))
                masked_magic = bytes(a & b for a, b in zip(sig.magic, sig.mask))
                if masked_chunk == masked_magic:
                    return DetectionResult(
                        format=sig.format,
                        confidence=0.95,
                        method="magic",
                        detected_by=f"magic:{sig.magic.hex()}",
                        file_size=file_size,
                        header_bytes=data[:32],
                    )
            else:
                if chunk == sig.magic:
                    return DetectionResult(
                        format=sig.format,
                        confidence=0.95,
                        method="magic",
                        detected_by=f"magic:{sig.magic.hex()}",
                        file_size=file_size,
                        header_bytes=data[:32],
                    )
        
        return None
    
    def _detect_by_extension(self, file_path: Path,
                              file_size: int) -> Optional[DetectionResult]:
        """Step 2: Fall back to file extension matching."""
        ext = file_path.suffix.lower()
        
        # Check for compound extensions
        name = str(file_path).lower()
        for compound_ext, fmt in sorted(EXTENSION_MAP.items(), 
                                          key=lambda x: -len(x[0])):
            if name.endswith(compound_ext):
                return DetectionResult(
                    format=fmt,
                    confidence=0.6,  # Extension is less reliable
                    method="extension",
                    detected_by=f"ext:{compound_ext}",
                    file_size=file_size,
                )
        
        return None
    
    def _detect_by_content_deep(self, data: bytes, file_path: Path,
                                 file_size: int) -> Optional[DetectionResult]:
        """Step 3: Deep content inspection."""
        fmt = _detect_by_content(data, str(file_path))
        if fmt:
            return DetectionResult(
                format=fmt,
                confidence=0.8,
                method="content",
                detected_by=f"content:{fmt.value}",
                file_size=file_size,
                header_bytes=data[:32],
            )
        return None
    
    def _detect_remote(self, source: str) -> DetectionResult:
        """Detect format of a remote source by URL pattern."""
        source_lower = source.lower()
        
        # Ollama
        if source_lower.startswith("ollama://") or "ollama" in source_lower:
            model_name = source.replace("ollama://", "").split("?")[0]
            return DetectionResult(
                format=ModelFormat.OLLAMA,
                confidence=0.9,
                method="remote",
                detected_by="url:ollama",
                metadata={"model_name": model_name},
            )
        
        # Hugging Face
        if source_lower.startswith("hf://") or "huggingface.co" in source_lower:
            # Extract model ID
            model_id = source.replace("hf://", "").split("?")[0]
            if "/" in model_id:
                return DetectionResult(
                    format=ModelFormat.HUGGINGFACE,
                    confidence=0.9,
                    method="remote",
                    detected_by="url:huggingface",
                    metadata={"model_id": model_id},
                )
        
        # Generic HTTP
        if source_lower.startswith("http://") or source_lower.startswith("https://"):
            # Check for known model hosts
            if "huggingface.co" in source_lower:
                return DetectionResult(
                    format=ModelFormat.HUGGINGFACE,
                    confidence=0.85,
                    method="remote",
                    detected_by="url:http_hf",
                    metadata={"url": source},
                )
            
            # Check for direct GGUF download
            if ".gguf" in source_lower:
                return DetectionResult(
                    format=ModelFormat.GGUF,
                    confidence=0.7,
                    method="remote",
                    detected_by="url:http_gguf",
                    metadata={"url": source},
                )
            
            return DetectionResult(
                format=ModelFormat.HTTP_MODEL,
                confidence=0.5,
                method="remote",
                detected_by="url:http_generic",
                metadata={"url": source},
            )
        
        return DetectionResult(
            format=ModelFormat.UNKNOWN,
            confidence=0.0,
            method="remote",
            detected_by="url:unknown",
        )
    
    def _cache_result(self, source: str, result: DetectionResult):
        """Cache a detection result."""
        self._cache[source] = result
        fmt_name = result.format.value
        self._stats["by_format"][fmt_name] = self._stats["by_format"].get(fmt_name, 0) + 1
        self._stats["by_method"][result.method] = self._stats["by_method"].get(result.method, 0) + 1
    
    def detect_batch(self, sources: List[str]) -> Dict[str, DetectionResult]:
        """Detect formats for multiple sources at once."""
        return {s: self.detect(s) for s in sources}
    
    def get_stats(self) -> Dict:
        """Get detection statistics."""
        return dict(self._stats)
    
    def clear_cache(self):
        """Clear the detection cache."""
        self._cache.clear()
    
    def print_summary(self):
        """Print a summary of the magic detection engine."""
        print(f"\n╔══════════════════════════════════════════════════════════════╗")
        print(f"║  MAGIC DETECTION ENGINE — Reverse Engineered Format Sniffing  ║")
        print(f"║  Signed: ~g87 | RawrXD                                       ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║                                                               ║")
        print(f"║  Magic Signatures: {len(MAGIC_DATABASE):>3d}                                  ║")
        print(f"║  Extension Mappings: {len(EXTENSION_MAP):>3d}                                 ║")
        print(f"║  Detectable Formats: {len(ModelFormat):>3d}                                 ║")
        print(f"║                                                               ║")
        print(f"║  Detection Methods:                                          ║")
        print(f"║    1. Magic Bytes — fastest, most reliable                    ║")
        print(f"║    2. File Extension — fallback                              ║")
        print(f"║    3. Deep Content — for ambiguous formats                   ║")
        print(f"║    4. Remote URL — for API-based models                      ║")
        print(f"║                                                               ║")
        print(f"║  Supported Formats:                                          ║")
        
        # Group formats by category
        categories = {
            "GGML Family": [ModelFormat.GGUF, ModelFormat.GGML,
                           ModelFormat.GGML_Q4_0, ModelFormat.GGML_Q4_1,
                           ModelFormat.GGML_Q5_0, ModelFormat.GGML_Q5_1,
                           ModelFormat.GGML_Q8_0],
            "PyTorch": [ModelFormat.PYTORCH, ModelFormat.PYTORCH_ZIP],
            "Hugging Face": [ModelFormat.SAFETENSORS, ModelFormat.HF_BIN,
                            ModelFormat.HF_MODEL, ModelFormat.HUGGINGFACE],
            "ONNX": [ModelFormat.ONNX],
            "TensorFlow": [ModelFormat.TENSORFLOW, ModelFormat.TFLITE],
            "Keras": [ModelFormat.KERAS_H5, ModelFormat.KERAS_V3],
            "Quantized": [ModelFormat.AWQ, ModelFormat.GPTQ, ModelFormat.EXL2],
            "Apple": [ModelFormat.COREML],
            "Intel": [ModelFormat.OPENVINO],
            "Raw/BLOB": [ModelFormat.BLOB, ModelFormat.RAW_F16, ModelFormat.RAW_F32],
            "Remote": [ModelFormat.OLLAMA, ModelFormat.HUGGINGFACE, ModelFormat.HTTP_MODEL],
            "Containers": [ModelFormat.ZIP, ModelFormat.TAR, ModelFormat.TARGZ],
            "Config": [ModelFormat.JSON_CONFIG, ModelFormat.YAML_CONFIG, ModelFormat.TOML_CONFIG],
        }
        
        for cat, fmts in categories.items():
            names = ", ".join(f.value for f in fmts)
            print(f"║    {cat:12s}: {names:45s}║")
        
        print(f"║                                                               ║")
        print(f"║  Stats:                                                       ║")
        print(f"║    Detections: {self._stats['detections']:>6d}                              ║")
        print(f"║    Cache hits: {self._stats['cache_hits']:>6d}                              ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")


# ═════════════════════════════════════════════════════════════════════
# STREAM FABRIC INTEGRATION
# ═════════════════════════════════════════════════════════════════════

class StreamRouter:
    """
    Routes model sources to the correct stream adapter based on magic detection.
    
    The router:
    1. Detects the format using MagicDetector
    2. Selects the appropriate stream adapter
    3. Opens the stream
    4. Returns a unified IModelStream interface
    """
    
    def __init__(self):
        self.detector = MagicDetector()
        self._adapters: Dict[ModelFormat, str] = {}
        self._routes: Dict[str, int] = {}
    
    def register_adapter(self, fmt: ModelFormat, adapter_name: str):
        """Register a stream adapter for a format."""
        self._adapters[fmt] = adapter_name
    
    def route(self, source: str) -> Tuple[DetectionResult, Optional[str]]:
        """
        Route a source to the correct adapter.
        
        Returns:
            (detection_result, adapter_name_or_None)
        """
        result = self.detector.detect(source)
        
        adapter = self._adapters.get(result.format)
        if not adapter:
            # Try generic fallbacks
            if result.is_container:
                adapter = self._adapters.get(ModelFormat.ZIP)
            elif result.is_remote:
                adapter = self._adapters.get(ModelFormat.HTTP_MODEL)
        
        route_key = f"{result.format.value}:{adapter or 'none'}"
        self._routes[route_key] = self._routes.get(route_key, 0) + 1
        
        return result, adapter
    
    def get_stats(self) -> Dict:
        """Get routing statistics."""
        return {
            "detector": self.detector.get_stats(),
            "routes": dict(self._routes),
            "adapters": dict(self._adapters),
        }


# ═════════════════════════════════════════════════════════════════════
# SMOKE TESTS
# ═════════════════════════════════════════════════════════════════════

def run_smoke_tests():
    """Run smoke tests for the magic detection engine."""
    print("\n" + "=" * 62)
    print("  MAGIC DETECTION SMOKE TESTS")
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
    
    detector = MagicDetector()
    
    # Test 1: GGUF detection
    print(f"\n  [Test Group 1: Magic Byte Detection]")
    result = detector._detect_by_magic(b"GGUF" + b"\x03\x00\x00\x00", Path("test.gguf"), 100)
    check("GGUF magic detected", result is not None and result.format == ModelFormat.GGUF)
    check("GGUF confidence high", result is not None and result.confidence >= 0.9)
    
    result = detector._detect_by_magic(b"ggml" + b"\x01\x00\x00\x00", Path("test.ggml"), 100)
    check("GGML magic detected", result is not None and result.format == ModelFormat.GGML)
    
    result = detector._detect_by_magic(b"PK\x03\x04" + b"\x00" * 20, Path("test.zip"), 100)
    # PyTorch ZIP (priority 80) matches before generic ZIP (priority 40)
    check("ZIP/PyTorch magic detected", result is not None and result.format in (ModelFormat.ZIP, ModelFormat.PYTORCH_ZIP))
    
    result = detector._detect_by_magic(b"\x1f\x8b\x08" + b"\x00" * 20, Path("test.gz"), 100)
    # CoreML (priority 60) matches before TARGZ (priority 40)
    check("GZIP/CoreML magic detected", result is not None and result.format in (ModelFormat.TARGZ, ModelFormat.COREML))
    
    result = detector._detect_by_magic(b"\x89HDF\r\n\x1a\n...", Path("test.h5"), 100)
    check("HDF5 magic detected", result is not None and result.format == ModelFormat.KERAS_H5)
    
    result = detector._detect_by_magic(b"\x80\x02...", Path("test.pt"), 100)
    check("PyTorch pickle detected", result is not None and result.format == ModelFormat.PYTORCH)
    
    result = detector._detect_by_magic(b"TFL3...", Path("test.tflite"), 100)
    check("TFLite magic detected", result is not None and result.format == ModelFormat.TFLITE)
    
    result = detector._detect_by_magic(b"AWQ\x00...", Path("test.awq"), 100)
    check("AWQ magic detected", result is not None and result.format == ModelFormat.AWQ)
    
    result = detector._detect_by_magic(b"EXL2...", Path("test.exl2"), 100)
    check("EXL2 magic detected", result is not None and result.format == ModelFormat.EXL2)
    
    # Test 2: Extension detection
    print(f"\n  [Test Group 2: Extension Detection]")
    for ext, fmt in [
        (".gguf", ModelFormat.GGUF),
        (".safetensors", ModelFormat.SAFETENSORS),
        (".pt", ModelFormat.PYTORCH),
        (".pth", ModelFormat.PYTORCH),
        (".onnx", ModelFormat.ONNX),
        (".tflite", ModelFormat.TFLITE),
        (".h5", ModelFormat.KERAS_H5),
        (".awq", ModelFormat.AWQ),
        (".exl2", ModelFormat.EXL2),
        (".json", ModelFormat.JSON_CONFIG),
        (".zip", ModelFormat.ZIP),
        (".tar", ModelFormat.TAR),
    ]:
        result = detector._detect_by_extension(Path(f"model{ext}"), 1000)
        check(f"Extension {ext} → {fmt.value}", 
              result is not None and result.format == fmt)
    
    # Test 3: Remote detection
    print(f"\n  [Test Group 3: Remote Detection]")
    result = detector._detect_remote("ollama://llama3.2:3b")
    check("Ollama URL detected", result.format == ModelFormat.OLLAMA)
    check("Ollama confidence high", result.confidence >= 0.8)
    
    result = detector._detect_remote("hf://meta-llama/Llama-3.2-3B")
    check("Hugging Face URL detected", result.format == ModelFormat.HUGGINGFACE)
    
    result = detector._detect_remote("https://example.com/models/llama-3.2-3b.Q4_K_M.gguf")
    check("HTTP GGUF URL detected", result.format == ModelFormat.GGUF)
    
    result = detector._detect_remote("https://example.com/model.bin")
    check("Generic HTTP detected", result.format == ModelFormat.HTTP_MODEL)
    
    # Test 4: Full detection pipeline
    print(f"\n  [Test Group 4: Full Detection Pipeline]")
    
    # Create a temporary GGUF-like file
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b"\x03\x00\x00\x00" + b"\x00" * 100)
        temp_path = f.name
    
    result = detector.detect(temp_path)
    check(f"Full pipeline detects GGUF", result.format == ModelFormat.GGUF)
    check(f"Full pipeline confidence high", result.confidence >= 0.9)
    check(f"Full pipeline method is magic", result.method == "magic")
    os.unlink(temp_path)
    
    # Test 5: Unknown format
    print(f"\n  [Test Group 5: Unknown Format]")
    with tempfile.NamedTemporaryFile(suffix=".xyz", delete=False, mode='wb') as f:
        f.write(b"\x00\x01\x02\x03" + b"\x00" * 100)
        temp_path = f.name
    
    result = detector.detect(temp_path)
    check("Unknown format returns UNKNOWN", result.format == ModelFormat.UNKNOWN)
    check("Unknown format has low confidence", result.confidence < 0.5)
    os.unlink(temp_path)
    
    # Test 6: Cache
    print(f"\n  [Test Group 6: Cache]")
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False, mode='wb') as f:
        f.write(b"GGUF" + b"\x03\x00\x00\x00" + b"\x00" * 100)
        temp_path = f.name
    
    result1 = detector.detect(temp_path)
    result2 = detector.detect(temp_path)
    check("Cache returns same result", result1.format == result2.format)
    check("Cache hit recorded", detector._stats["cache_hits"] > 0)
    os.unlink(temp_path)
    
    # Test 7: Batch detection
    print(f"\n  [Test Group 7: Batch Detection]")
    sources = [
        "ollama://llama3.2:3b",
        "hf://meta-llama/Llama-3.2-3B",
        "https://example.com/model.gguf",
    ]
    results = detector.detect_batch(sources)
    check("Batch returns all results", len(results) == 3)
    check("Batch detects Ollama", results[sources[0]].format == ModelFormat.OLLAMA)
    check("Batch detects HF", results[sources[1]].format == ModelFormat.HUGGINGFACE)
    check("Batch detects HTTP GGUF", results[sources[2]].format == ModelFormat.GGUF)
    
    # Test 8: Deep content detection
    print(f"\n  [Test Group 8: Deep Content Detection]")
    
    # SafeTensors deep check
    header = json.dumps({"__metadata__": {"format": "pt"}}).encode()
    header_size = struct.pack('<Q', len(header))
    st_data = header_size + header + b"\x00" * 100
    fmt = _detect_by_content(st_data, "test.safetensors")
    check("SafeTensors deep content detected", fmt == ModelFormat.SAFETENSORS)
    
    # JSON config deep check
    json_data = b'{"model_type": "llama", "architectures": ["LlamaForCausalLM"]}'
    fmt = _detect_by_content(json_data, "config.json")
    check("JSON config deep content detected", fmt == ModelFormat.JSON_CONFIG)
    
    # Test 9: Format properties
    print(f"\n  [Test Group 9: Format Properties]")
    result = DetectionResult(format=ModelFormat.GGUF, confidence=1.0, method="test", detected_by="test")
    check("GGUF is known", result.is_known)
    check("GGUF is quantized", result.is_quantized)
    check("GGUF is not remote", not result.is_remote)
    check("GGUF is not container", not result.is_container)
    
    result = DetectionResult(format=ModelFormat.OLLAMA, confidence=1.0, method="test", detected_by="test")
    check("Ollama is remote", result.is_remote)
    check("Ollama is not quantized", not result.is_quantized)
    
    result = DetectionResult(format=ModelFormat.ZIP, confidence=1.0, method="test", detected_by="test")
    check("ZIP is container", result.is_container)
    
    result = DetectionResult(format=ModelFormat.UNKNOWN, confidence=0.0, method="test", detected_by="test")
    check("Unknown is not known", not result.is_known)
    
    # Test 10: StreamRouter
    print(f"\n  [Test Group 10: StreamRouter]")
    router = StreamRouter()
    router.register_adapter(ModelFormat.GGUF, "GGUFStreamAdapter")
    router.register_adapter(ModelFormat.OLLAMA, "OllamaStreamAdapter")
    router.register_adapter(ModelFormat.HUGGINGFACE, "HFStreamAdapter")
    
    result, adapter = router.route("ollama://llama3.2:3b")
    check("Router routes Ollama", adapter == "OllamaStreamAdapter")
    
    result, adapter = router.route("hf://meta-llama/Llama-3.2-3B")
    check("Router routes HF", adapter == "HFStreamAdapter")
    
    # Test 11: Stats
    print(f"\n  [Test Group 11: Statistics]")
    stats = detector.get_stats()
    check("Stats has detections", "detections" in stats)
    check("Stats has cache_hits", "cache_hits" in stats)
    check("Stats has by_format", "by_format" in stats)
    check("Stats has by_method", "by_method" in stats)
    
    # Test 12: Clear cache
    print(f"\n  [Test Group 12: Clear Cache]")
    detector.clear_cache()
    check("Cache cleared", len(detector._cache) == 0)
    
    # Test 13: All magic signatures have valid formats
    print(f"\n  [Test Group 13: Magic Signature Validation]")
    for sig in MAGIC_DATABASE:
        check(f"Signature {sig.magic.hex()} has valid format", 
              sig.format in ModelFormat)
        check(f"Signature {sig.magic.hex()} has priority >= 0", 
              sig.priority >= 0)
    
    # Test 14: All extension mappings have valid formats
    print(f"\n  [Test Group 14: Extension Mapping Validation]")
    for ext, fmt in EXTENSION_MAP.items():
        check(f"Extension {ext} maps to valid format", fmt in ModelFormat)
    
    # Test 15: DetectionResult properties
    print(f"\n  [Test Group 15: DetectionResult Properties]")
    result = DetectionResult(format=ModelFormat.GGUF, confidence=0.95, method="magic", detected_by="test")
    check("Result has format", result.format == ModelFormat.GGUF)
    check("Result has confidence", result.confidence == 0.95)
    check("Result has method", result.method == "magic")
    check("Result has detected_by", result.detected_by == "test")
    
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
        detector = MagicDetector()
        detector.print_summary()
        
        print(f"\n  Demo detections:")
        test_sources = [
            "ollama://llama3.2:3b",
            "hf://meta-llama/Llama-3.2-3B",
            "https://huggingface.co/meta-llama/Llama-3.2-3B-GGUF/resolve/main/model.q4_k_m.gguf",
            "model.safetensors",
            "model.pt",
            "model.onnx",
            "model.tflite",
            "model.h5",
            "model.awq",
            "model.exl2",
            "model.zip",
            "model.tar.gz",
            "config.json",
        ]
        
        for src in test_sources:
            result = detector.detect(src)
            confidence_bar = "█" * int(result.confidence * 20)
            print(f"  {src:50s} → {result.format.value:15s} [{confidence_bar}] ({result.confidence:.0%})")
    else:
        run_smoke_tests()
