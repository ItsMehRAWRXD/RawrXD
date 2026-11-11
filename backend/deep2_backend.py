#!/usr/bin/env python3
"""
Deep2 Streaming Backend for RawrEngine.

Provides a local GGUF model streaming interface compatible with RawrEngine's
/api/chat and /api/agent/wish endpoints.

This implementation uses a practical approach for the vertical slice:
- Loads GGUF model metadata
- Provides token-by-token streaming via callback
- Integrates with RawrEngine's existing tool server
"""

from __future__ import annotations

import json
import os
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional


@dataclass
class ModelConfig:
    """Model configuration extracted from GGUF metadata."""
    name: str
    architecture: str
    hidden_dim: int
    num_layers: int
    num_heads: int
    num_kv_heads: int
    head_dim: int
    vocab_size: int
    max_seq_len: int
    rope_theta: float = 10000.0
    rope_scaling: Optional[dict] = None


@dataclass
class TokenizerInfo:
    """Tokenizer configuration from GGUF metadata."""
    vocab: list[str]
    merges: Optional[list[str]] = None
    bos_token: int = 1
    eos_token: int = 2
    unk_token: int = 0
    pad_token: Optional[int] = None


class GGUFMetadataParser:
    """Parse GGUF metadata without loading full model weights."""
    
    @staticmethod
    def parse_gguf_metadata(gguf_path: str) -> tuple[ModelConfig, TokenizerInfo]:
        """Extract model config and tokenizer info from GGUF file."""
        with open(gguf_path, 'rb') as f:
            # Read header
            magic = struct.unpack('<I', f.read(4))[0]
            if magic != 0x46554747:  # "GGUF"
                raise ValueError("Not a valid GGUF file")
            
            version = struct.unpack('<I', f.read(4))[0]
            tensor_count = struct.unpack('<Q', f.read(8))[0]
            metadata_kv_count = struct.unpack('<Q', f.read(8))[0]
            
            # Parse metadata
            metadata = {}
            for _ in range(metadata_kv_count):
                key = GGUFMetadataParser._read_string(f)
                value_type = struct.unpack('<I', f.read(4))[0]
                value = GGUFMetadataParser._read_value(f, value_type)
                metadata[key] = value
            
            # Extract model config
            config = ModelConfig(
                name=Path(gguf_path).stem,
                architecture=metadata.get('general.architecture', 'unknown'),
                hidden_dim=metadata.get('llama.embedding_length', 4096),
                num_layers=metadata.get('llama.block_count', 32),
                num_heads=metadata.get('llama.attention.head_count', 32),
                num_kv_heads=metadata.get('llama.attention.head_count_kv', 32),
                head_dim=metadata.get('llama.attention.head_dim', 128),
                vocab_size=metadata.get('llama.vocab_size', 32000),
                max_seq_len=metadata.get('llama.context_length', 4096),
                rope_theta=metadata.get('llama.rope.freq_base', 10000.0),
            )
            
            # Extract tokenizer
            vocab = metadata.get('tokenizer.ggml.tokens', [])
            if isinstance(vocab, list):
                vocab = [v.encode('utf-8').decode('utf-8', errors='replace') if isinstance(v, bytes) else str(v) for v in vocab]
            else:
                vocab = [chr(i) for i in range(256)]  # Fallback byte vocab
            
            merges = metadata.get('tokenizer.ggml.merges', None)
            
            tokenizer = TokenizerInfo(
                vocab=vocab,
                merges=merges,
                bos_token=metadata.get('tokenizer.ggml.bos_token_id', 1),
                eos_token=metadata.get('tokenizer.ggml.eos_token_id', 2),
                unk_token=metadata.get('tokenizer.ggml.unknown_token_id', 0),
            )
            
            return config, tokenizer
    
    @staticmethod
    def _read_string(f) -> str:
        length = struct.unpack('<Q', f.read(8))[0]
        return f.read(length).decode('utf-8', errors='replace')
    
    @staticmethod
    def _read_value(f, value_type: int):
        """Read a GGUF metadata value based on type."""
        if value_type == 8:  # STRING
            return GGUFMetadataParser._read_string(f)
        elif value_type == 4:  # UINT32
            return struct.unpack('<I', f.read(4))[0]
        elif value_type == 5:  # INT32
            return struct.unpack('<i', f.read(4))[0]
        elif value_type == 6:  # FLOAT32
            return struct.unpack('<f', f.read(4))[0]
        elif value_type == 7:  # BOOL
            return bool(struct.unpack('<B', f.read(1))[0])
        elif value_type == 9:  # ARRAY
            array_type = struct.unpack('<I', f.read(4))[0]
            count = struct.unpack('<Q', f.read(8))[0]
            return [GGUFMetadataParser._read_value(f, array_type) for _ in range(count)]
        else:
            # Skip unknown types
            type_sizes = {0: 1, 1: 1, 2: 2, 3: 2, 10: 8, 11: 8, 12: 8}
            size = type_sizes.get(value_type, 1)
            f.seek(size, os.SEEK_CUR)
            return None


class SimpleTokenizer:
    """Simple SentencePiece/BPE tokenizer for GGUF models."""
    
    def __init__(self, tokenizer_info: TokenizerInfo):
        self.vocab = tokenizer_info.vocab
        self.merges = tokenizer_info.merges or []
        self.bos_token = tokenizer_info.bos_token
        self.eos_token = tokenizer_info.eos_token
        self.unk_token = tokenizer_info.unk_token
        self.pad_token = tokenizer_info.pad_token
        
        # Build reverse vocab
        self.token_to_id = {token: i for i, token in enumerate(self.vocab)}
        
        # Build merge rules for BPE
        self.merge_rules = {}
        for i, merge in enumerate(self.merges):
            parts = merge.split()
            if len(parts) == 2:
                self.merge_rules[(parts[0], parts[1])] = i
    
    def _byte_fallback_encode(self, text: str) -> list[int]:
        """Encode using byte-level fallback for unknown characters."""
        tokens = []
        for byte in text.encode('utf-8'):
            # GGUF byte tokens are typically at indices 3-258 (0,1,2 reserved for special)
            byte_token = f"<0x{byte:02X}>"
            if byte_token in self.token_to_id:
                tokens.append(self.token_to_id[byte_token])
            else:
                tokens.append(self.unk_token)
        return tokens
    
    def encode(self, text: str) -> list[int]:
        """Encode text to token IDs using BPE with SentencePiece conventions."""
        if not text:
            return []
        
        # Add BOS token if vocab has it
        tokens = []
        if self.bos_token >= 0 and self.bos_token < len(self.vocab):
            tokens.append(self.bos_token)
        
        # Normalize: replace spaces with SentencePiece space marker ▁
        # Split into words/segments
        text = text.replace(' ', '▁')
        
        # Simple BPE encoding: try to match longest vocabulary pieces
        # This is a simplified version - production would use proper SPM
        i = 0
        while i < len(text):
            # Try longest match first
            matched = False
            for length in range(min(20, len(text) - i), 0, -1):
                piece = text[i:i+length]
                if piece in self.token_to_id:
                    tokens.append(self.token_to_id[piece])
                    i += length
                    matched = True
                    break
            
            if not matched:
                # Fallback to byte encoding for unknown character
                char = text[i]
                byte_tokens = self._byte_fallback_encode(char)
                tokens.extend(byte_tokens)
                i += 1
        
        # Add EOS token
        if self.eos_token >= 0 and self.eos_token < len(self.vocab):
            tokens.append(self.eos_token)
        
        return tokens
    
    def decode(self, tokens: list[int]) -> str:
        """Decode token IDs to text with proper SentencePiece handling."""
        if not tokens:
            return ""
        
        pieces = []
        for token in tokens:
            if 0 <= token < len(self.vocab):
                pieces.append(self.vocab[token])
            else:
                pieces.append('�')
        
        # Join pieces and handle SentencePiece conventions
        text = ''.join(pieces)
        
        # Remove BOS/EOS markers if present
        if self.bos_token >= 0 and self.bos_token < len(self.vocab):
            bos_piece = self.vocab[self.bos_token]
            if text.startswith(bos_piece):
                text = text[len(bos_piece):]
        
        if self.eos_token >= 0 and self.eos_token < len(self.vocab):
            eos_piece = self.vocab[self.eos_token]
            if text.endswith(eos_piece):
                text = text[:-len(eos_piece)]
        
        # Convert SentencePiece space marker ▁ to actual space
        text = text.replace('\u2581', ' ')
        
        # Handle byte fallback tokens <0xXX>
        import re
        def replace_byte_token(match):
            hex_val = match.group(1)
            try:
                return bytes([int(hex_val, 16)]).decode('utf-8', errors='replace')
            except:
                return '�'
        
        text = re.sub(r'<0x([0-9A-Fa-f]{2})>', replace_byte_token, text)
        
        return text


class Deep2StreamingBackend:
    """
    Deep2-compatible streaming inference backend.
    
    For the vertical slice, this provides a practical streaming interface
    that can be swapped with a real Deep2 engine integration.
    """
    
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.config: Optional[ModelConfig] = None
        self.tokenizer: Optional[SimpleTokenizer] = None
        self._initialized = False
        self._lock = threading.Lock()
        
        # Generation state
        self._kv_cache: list[Any] = []
        self._position = 0
    
    def initialize(self) -> bool:
        """Initialize the backend by loading model metadata."""
        try:
            config, tokenizer_info = GGUFMetadataParser.parse_gguf_metadata(self.model_path)
            self.config = config
            self.tokenizer = SimpleTokenizer(tokenizer_info)
            self._initialized = True
            print(f"[Deep2Backend] Initialized: {config.name} ({config.architecture})")
            print(f"[Deep2Backend] Layers: {config.num_layers}, Heads: {config.num_heads}, Dim: {config.hidden_dim}")
            return True
        except Exception as e:
            print(f"[Deep2Backend] Initialization failed: {e}")
            return False
    
    def is_initialized(self) -> bool:
        return self._initialized
    
    def tokenize(self, text: str) -> list[int]:
        """Tokenize input text."""
        if not self.tokenizer:
            raise RuntimeError("Backend not initialized")
        return self.tokenizer.encode(text)
    
    def detokenize(self, tokens: list[int]) -> str:
        """Detokenize token IDs to text."""
        if not self.tokenizer:
            raise RuntimeError("Backend not initialized")
        return self.tokenizer.decode(tokens)
    
    def generate_stream(
        self,
        prompt: str,
        max_tokens: int = 256,
        temperature: float = 0.7,
        top_p: float = 0.9,
        callback: Optional[Callable[[str], bool]] = None
    ) -> str:
        """
        Generate text with streaming callback.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            top_p: Top-p sampling
            callback: Called for each token chunk, return False to stop
            
        Returns:
            Full generated text
        """
        if not self._initialized:
            raise RuntimeError("Backend not initialized")
        
        # For the vertical slice, we simulate streaming by generating
        # a coherent response token by token
        # In production, this would call the actual Deep2 engine
        
        tokens = self.tokenize(prompt)
        generated_tokens = []
        accumulated = ""
        
        # Simulate token-by-token generation for demo
        # Real implementation would call Deep2Engine.generate() with callback
        response = self._generate_response(prompt)
        response_tokens = self.tokenize(response)
        
        for i, token in enumerate(response_tokens[:max_tokens]):
            generated_tokens.append(token)
            piece = self.detokenize([token])
            accumulated += piece
            
            # Debug logging
            if i < 10:  # Log first 10 tokens for debugging
                vocab_piece = self.tokenizer.vocab[token] if 0 <= token < len(self.tokenizer.vocab) else "OOB"
                # Safe logging for console
                safe_piece = vocab_piece.replace('\u2581', '[SP]')
                print(f"[Deep2Backend] Token {i}: id={token} piece='{safe_piece}' decoded='{piece}'")
            
            if callback:
                if not callback(piece):
                    break
            
            # Small delay to simulate streaming
            time.sleep(0.01)
        
        return accumulated
    
    def generate(
        self,
        prompt: str,
        max_tokens: int = 256,
        temperature: float = 0.7,
        top_p: float = 0.9
    ) -> str:
        """Generate text without streaming (blocking)."""
        return self.generate_stream(prompt, max_tokens, temperature, top_p, callback=None)
    
    def _generate_response(self, prompt: str) -> str:
        """Generate a response for the given prompt.
        
        In production, this would call the actual Deep2 engine.
        For the vertical slice, we provide context-aware responses.
        """
        prompt_lower = prompt.lower()
        
        # Context-aware responses for coding tasks
        if "read" in prompt_lower and "file" in prompt_lower:
            return "I'll read the file for you. Let me use the file_reader tool."
        elif "write" in prompt_lower or "edit" in prompt_lower or "patch" in prompt_lower:
            return "I'll help you edit the file. Let me use the code_edit tool."
        elif "list" in prompt_lower or "directory" in prompt_lower:
            return "I'll list the directory contents using the fs_list tool."
        elif "search" in prompt_lower or "find" in prompt_lower:
            return "I'll search for that using the search tool."
        elif "compile" in prompt_lower or "build" in prompt_lower or "test" in prompt_lower:
            return "I'll run the build/test commands using the terminal_exec tool."
        elif "git" in prompt_lower:
            return "I'll check the git status using the git_status tool."
        elif "hello" in prompt_lower or "hi" in prompt_lower:
            return "Hello! I'm ready to help with your coding tasks. What would you like me to do?"
        elif "plan" in prompt_lower:
            return "I'll create a plan for this task. Let me break it down into steps."
        else:
            # Generic helpful response
            return f"I understand you want to: {prompt[:100]}. Let me help you with that by using the available tools."


class Deep2BackendManager:
    """Manages Deep2 backend instances for RawrEngine."""
    
    def __init__(self):
        self.backends: dict[str, Deep2StreamingBackend] = {}
        self.current_model: Optional[str] = None
        self._lock = threading.Lock()
    
    def register_model(self, model_id: str, model_path: str) -> bool:
        """Register a model with the backend."""
        with self._lock:
            if model_id in self.backends:
                return True
            
            backend = Deep2StreamingBackend(model_path)
            if backend.initialize():
                self.backends[model_id] = backend
                if self.current_model is None:
                    self.current_model = model_id
                return True
            return False
    
    def get_backend(self, model_id: Optional[str] = None) -> Optional[Deep2StreamingBackend]:
        """Get a backend instance."""
        with self._lock:
            model = model_id or self.current_model
            if model and model in self.backends:
                return self.backends[model]
            return None
    
    def set_current_model(self, model_id: str) -> bool:
        """Set the current default model."""
        with self._lock:
            if model_id in self.backends:
                self.current_model = model_id
                return True
            return False
    
    def list_models(self) -> list[str]:
        """List registered models."""
        with self._lock:
            return list(self.backends.keys())


# Global backend manager instance
_BACKEND_MANAGER = Deep2BackendManager()


def get_backend_manager() -> Deep2BackendManager:
    """Get the global backend manager."""
    return _BACKEND_MANAGER


def initialize_deep2_models(model_dirs: list[str]) -> int:
    """Scan directories for GGUF models and register them."""
    count = 0
    for model_dir in model_dirs:
        if not os.path.isdir(model_dir):
            continue
        for root, _, files in os.walk(model_dir):
            for fname in files:
                if fname.endswith('.gguf'):
                    model_path = os.path.join(root, fname)
                    model_id = fname
                    if _BACKEND_MANAGER.register_model(model_id, model_path):
                        count += 1
    return count


if __name__ == "__main__":
    # Test the backend
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python deep2_backend.py <model.gguf> [prompt]")
        sys.exit(1)
    
    model_path = sys.argv[1]
    prompt = sys.argv[2] if len(sys.argv) > 2 else "Hello, how are you?"
    
    backend = Deep2StreamingBackend(model_path)
    if backend.initialize():
        print(f"\nGenerating response for: '{prompt}'")
        print("-" * 40)
        
        def stream_callback(chunk: str) -> bool:
            print(chunk, end='', flush=True)
            return True
        
        response = backend.generate_stream(prompt, callback=stream_callback)
        print(f"\n\nFull response: {response}")
    else:
        print("Failed to initialize backend")
        sys.exit(1)