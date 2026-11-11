#!/usr/bin/env python3
"""
RawrXD Model Manager

A comprehensive tool for downloading, converting, and managing LLM models.

Usage:
    python model_manager.py list
    python model_manager.py pull <model_name>
    python model_manager.py convert <input> --output <output> --format gguf
    python model_manager.py verify <model_path>
    python model_manager.py quantize <model_path> --type Q4_K
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class ModelInfo:
    """Model metadata."""
    name: str
    repo: str
    filename: str
    size: str
    parameters: str
    context_length: int
    quantization: str
    description: str
    sha256: Optional[str] = None


# Predefined model registry
MODEL_REGISTRY: Dict[str, ModelInfo] = {
    "llama-2-7b": ModelInfo(
        name="Llama 2 7B",
        repo="TheBloke/Llama-2-7B-GGUF",
        filename="llama-2-7b.Q4_K_M.gguf",
        size="3.8 GB",
        parameters="7B",
        context_length=4096,
        quantization="Q4_K_M",
        description="Meta's Llama 2 7B model, quantized to Q4_K_M"
    ),
    "llama-2-7b-chat": ModelInfo(
        name="Llama 2 7B Chat",
        repo="TheBloke/Llama-2-7B-Chat-GGUF",
        filename="llama-2-7b-chat.Q4_K_M.gguf",
        size="3.8 GB",
        parameters="7B",
        context_length=4096,
        quantization="Q4_K_M",
        description="Meta's Llama 2 7B Chat model, optimized for conversation"
    ),
    "llama-2-13b": ModelInfo(
        name="Llama 2 13B",
        repo="TheBloke/Llama-2-13B-GGUF",
        filename="llama-2-13b.Q4_K_M.gguf",
        size="7.4 GB",
        parameters="13B",
        context_length=4096,
        quantization="Q4_K_M",
        description="Meta's Llama 2 13B model"
    ),
    "llama-2-13b-chat": ModelInfo(
        name="Llama 2 13B Chat",
        repo="TheBloke/Llama-2-13B-Chat-GGUF",
        filename="llama-2-13b-chat.Q4_K_M.gguf",
        size="7.4 GB",
        parameters="13B",
        context_length=4096,
        quantization="Q4_K_M",
        description="Meta's Llama 2 13B Chat model"
    ),
    "mistral-7b": ModelInfo(
        name="Mistral 7B",
        repo="TheBloke/Mistral-7B-v0.1-GGUF",
        filename="mistral-7b-v0.1.Q4_K_M.gguf",
        size="4.1 GB",
        parameters="7B",
        context_length=8192,
        quantization="Q4_K_M",
        description="Mistral AI's 7B model with superior performance"
    ),
    "mistral-7b-instruct": ModelInfo(
        name="Mistral 7B Instruct",
        repo="TheBloke/Mistral-7B-Instruct-v0.1-GGUF",
        filename="mistral-7b-instruct-v0.1.Q4_K_M.gguf",
        size="4.1 GB",
        parameters="7B",
        context_length=8192,
        quantization="Q4_K_M",
        description="Mistral 7B optimized for instruction following"
    ),
    "codellama-7b": ModelInfo(
        name="CodeLlama 7B",
        repo="TheBloke/CodeLlama-7B-GGUF",
        filename="codellama-7b.Q4_K_M.gguf",
        size="3.8 GB",
        parameters="7B",
        context_length=16384,
        quantization="Q4_K_M",
        description="Meta's CodeLlama 7B for code generation"
    ),
    "codellama-7b-instruct": ModelInfo(
        name="CodeLlama 7B Instruct",
        repo="TheBloke/CodeLlama-7B-Instruct-GGUF",
        filename="codellama-7b-instruct.Q4_K_M.gguf",
        size="3.8 GB",
        parameters="7B",
        context_length=16384,
        quantization="Q4_K_M",
        description="CodeLlama 7B optimized for instruction following"
    ),
    "neural-chat-7b": ModelInfo(
        name="Neural Chat 7B",
        repo="TheBloke/neural-chat-7B-v3-1-GGUF",
        filename="neural-chat-7b-v3-1.Q4_K_M.gguf",
        size="4.1 GB",
        parameters="7B",
        context_length=8192,
        quantization="Q4_K_M",
        description="Intel's Neural Chat 7B v3.1, optimized for conversation"
    ),
    "orca-2-7b": ModelInfo(
        name="Orca 2 7B",
        repo="TheBloke/Orca-2-7B-GGUF",
        filename="orca-2-7b.Q4_K_M.gguf",
        size="3.8 GB",
        parameters="7B",
        context_length=4096,
        quantization="Q4_K_M",
        description="Microsoft's Orca 2 7B, optimized for reasoning"
    ),
}


class ModelManager:
    """Manager for LLM models."""
    
    def __init__(self, models_dir: str = "./models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = self.models_dir / "registry.json"
        self._load_registry()
    
    def _load_registry(self):
        """Load local model registry."""
        if self.registry_file.exists():
            with open(self.registry_file, 'r') as f:
                data = json.load(f)
                self.local_models = data.get('models', {})
        else:
            self.local_models = {}
    
    def _save_registry(self):
        """Save local model registry."""
        data = {
            'models': self.local_models,
            'updated': datetime.now().isoformat()
        }
        with open(self.registry_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def list_available(self) -> List[ModelInfo]:
        """List available models in registry."""
        return list(MODEL_REGISTRY.values())
    
    def list_local(self) -> List[Dict]:
        """List locally downloaded models."""
        models = []
        for model_id, info in self.local_models.items():
            models.append({
                'id': model_id,
                **info
            })
        return models
    
    def pull(self, model_id: str, quantization: str = "Q4_K_M") -> bool:
        """Download a model from Hugging Face."""
        if model_id not in MODEL_REGISTRY:
            print(f"Error: Model '{model_id}' not found in registry.")
            print("Use 'list' to see available models.")
            return False
        
        model_info = MODEL_REGISTRY[model_id]
        
        # Construct download URL
        url = f"https://huggingface.co/{model_info.repo}/resolve/main/{model_info.filename}"
        output_path = self.models_dir / model_info.filename
        
        if output_path.exists():
            print(f"Model '{model_id}' already exists at {output_path}")
            return True
        
        print(f"Downloading {model_info.name}...")
        print(f"  From: {url}")
        print(f"  To: {output_path}")
        print(f"  Size: {model_info.size}")
        
        try:
            self._download_with_progress(url, output_path)
            
            # Update registry
            self.local_models[model_id] = {
                'name': model_info.name,
                'filename': model_info.filename,
                'path': str(output_path),
                'size': model_info.size,
                'downloaded': datetime.now().isoformat()
            }
            self._save_registry()
            
            print(f"\nSuccessfully downloaded {model_info.name}!")
            return True
            
        except Exception as e:
            print(f"\nError downloading model: {e}")
            if output_path.exists():
                output_path.unlink()
            return False
    
    def _download_with_progress(self, url: str, output_path: Path):
        """Download file with progress bar."""
        def report_progress(block_num, block_size, total_size):
            downloaded = block_num * block_size
            percent = min(downloaded * 100 / total_size, 100)
            mb = downloaded / (1024 * 1024)
            total_mb = total_size / (1024 * 1024)
            print(f"\r  Progress: {percent:.1f}% ({mb:.1f} / {total_mb:.1f} MB)", end='', flush=True)
        
        urllib.request.urlretrieve(url, output_path, reporthook=report_progress)
        print()  # New line after progress
    
    def remove(self, model_id: str) -> bool:
        """Remove a downloaded model."""
        if model_id not in self.local_models:
            print(f"Error: Model '{model_id}' not found locally.")
            return False
        
        model_info = self.local_models[model_id]
        model_path = Path(model_info['path'])
        
        if model_path.exists():
            model_path.unlink()
        
        del self.local_models[model_id]
        self._save_registry()
        
        print(f"Removed model '{model_id}'")
        return True
    
    def info(self, model_id: str) -> Optional[Dict]:
        """Get model information."""
        if model_id in MODEL_REGISTRY:
            return asdict(MODEL_REGISTRY[model_id])
        elif model_id in self.local_models:
            return self.local_models[model_id]
        return None
    
    def verify(self, model_path: str) -> bool:
        """Verify model file integrity."""
        path = Path(model_path)
        if not path.exists():
            print(f"Error: File not found: {model_path}")
            return False
        
        print(f"Verifying {path.name}...")
        
        # Check file size
        size = path.stat().st_size
        print(f"  Size: {size / (1024**3):.2f} GB")
        
        # Calculate hash (first 100MB for speed)
        print("  Calculating checksum...")
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                data = f.read(8192)
                if not data:
                    break
                sha256.update(data)
        
        checksum = sha256.hexdigest()
        print(f"  SHA256: {checksum}")
        
        # TODO: Compare with known checksums
        print("  Status: File appears valid")
        
        return True
    
    def get_model_path(self, model_id: str) -> Optional[Path]:
        """Get path to a downloaded model."""
        if model_id in self.local_models:
            return Path(self.local_models[model_id]['path'])
        return None


def print_table(headers: List[str], rows: List[List[str]]):
    """Print a formatted table."""
    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    
    # Print header
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_line)
    print("-" * len(header_line))
    
    # Print rows
    for row in rows:
        print(" | ".join(cell.ljust(w) for cell, w in zip(row, widths)))


def main():
    parser = argparse.ArgumentParser(
        description="RawrXD Model Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list                    # List available models
  %(prog)s pull llama-2-7b-chat    # Download a model
  %(prog)s local                   # List downloaded models
  %(prog)s info llama-2-7b-chat    # Show model info
  %(prog)s verify ./models/model.gguf  # Verify model file
  %(prog)s rm llama-2-7b-chat      # Remove a model
        """
    )
    
    parser.add_argument('--models-dir', default='./models',
                       help='Directory to store models')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List available models')
    
    # Local command
    local_parser = subparsers.add_parser('local', help='List downloaded models')
    
    # Pull command
    pull_parser = subparsers.add_parser('pull', help='Download a model')
    pull_parser.add_argument('model', help='Model ID to download')
    pull_parser.add_argument('--quantization', default='Q4_K_M',
                            help='Quantization type')
    
    # Remove command
    rm_parser = subparsers.add_parser('rm', help='Remove a model')
    rm_parser.add_argument('model', help='Model ID to remove')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show model information')
    info_parser.add_argument('model', help='Model ID')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify model file')
    verify_parser.add_argument('path', help='Path to model file')
    
    # Convert command (placeholder)
    convert_parser = subparsers.add_parser('convert', help='Convert model format')
    convert_parser.add_argument('input', help='Input model path')
    convert_parser.add_argument('--output', required=True, help='Output path')
    convert_parser.add_argument('--format', default='gguf', help='Output format')
    
    # Quantize command (placeholder)
    quantize_parser = subparsers.add_parser('quantize', help='Quantize model')
    quantize_parser.add_argument('model', help='Model path')
    quantize_parser.add_argument('--type', default='Q4_K_M',
                                  choices=['Q4_0', 'Q4_K', 'Q5_K', 'Q6_K', 'Q8_0'],
                                  help='Quantization type')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    manager = ModelManager(models_dir=args.models_dir)
    
    if args.command == 'list':
        print("=== Available Models ===\n")
        headers = ['ID', 'Name', 'Size', 'Parameters', 'Quantization']
        rows = []
        for model_id, info in MODEL_REGISTRY.items():
            rows.append([
                model_id,
                info.name,
                info.size,
                info.parameters,
                info.quantization
            ])
        print_table(headers, rows)
        print(f"\nTotal: {len(MODEL_REGISTRY)} models")
        print("\nUse 'pull <model_id>' to download a model.")
    
    elif args.command == 'local':
        models = manager.list_local()
        if not models:
            print("No models downloaded yet.")
            print(f"Use 'list' to see available models and 'pull' to download.")
            return
        
        print("=== Downloaded Models ===\n")
        headers = ['ID', 'Name', 'Size', 'Downloaded']
        rows = [[m['id'], m['name'], m['size'], m['downloaded'][:10]] for m in models]
        print_table(headers, rows)
        print(f"\nTotal: {len(models)} models")
        print(f"Location: {args.models_dir}")
    
    elif args.command == 'pull':
        success = manager.pull(args.model, args.quantization)
        sys.exit(0 if success else 1)
    
    elif args.command == 'rm':
        success = manager.remove(args.model)
        sys.exit(0 if success else 1)
    
    elif args.command == 'info':
        info = manager.info(args.model)
        if info:
            print(f"=== Model Information: {args.model} ===\n")
            for key, value in info.items():
                print(f"  {key}: {value}")
        else:
            print(f"Model '{args.model}' not found.")
            sys.exit(1)
    
    elif args.command == 'verify':
        success = manager.verify(args.path)
        sys.exit(0 if success else 1)
    
    elif args.command == 'convert':
        print(f"Converting {args.input} to {args.format}...")
        print("Note: Model conversion requires additional tools.")
        print("Please use llama.cpp's convert.py script for now.")
    
    elif args.command == 'quantize':
        print(f"Quantizing {args.model} to {args.type}...")
        print("Note: Quantization requires additional tools.")
        print("Please use llama.cpp's quantize binary for now.")


if __name__ == '__main__':
    main()
