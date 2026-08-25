# RGUF source drop

Zero-third-party C++17 foundation for a RawrXD-native, block-addressable model container.

## Current implementation
- RGUF binary header/block metadata.
- Block CRC32 integrity.
- Atomic-safe runtime block ownership through `shared_ptr`/mutex lifetime management.
- Windows AES-256-GCM through OS CNG (`bcrypt`); no third-party crypto library.
- Custom symmetric Q4 codec (`RGUFQuant`) for float arrays.
- Patch file generation and runtime staging.
- CMake target and CLI.

## Important scope
The GGUF packer deliberately refuses to emit a corrupt model when it encounters a tensor-directory case it does not fully parse. The current `Writer::pack` contains the GGUF header/metadata parser and the safety boundary where the complete tensor directory parser should be integrated with RawrXD's existing GGUF loader. It does not pretend to be a complete GGUF-to-RGUF converter.

The runtime patch path stages a replacement block in memory. Persistent in-place rewriting is intentionally separate so an active mapped/read block is never overwritten underneath inference.

## Build
Windows/MSVC:
```
cmake -S . -B build -G Ninja
cmake --build build --config Release
```

Pack syntax:
```
rguf_tool pack model.gguf model.rguf
rguf_tool pack model.gguf model.rguf <64-hex-character-key>
rguf_tool inspect model.rguf
```

AES-GCM is authenticated encryption. Windows CNG supports AES-GCM and Microsoft explicitly recommends authenticated modes such as GCM over ECB for production data. 
