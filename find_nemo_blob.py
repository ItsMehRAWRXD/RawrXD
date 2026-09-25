#!/usr/bin/env python3
"""Find the on-disk Ollama blob for nemotron-3.5-lightning:30b"""
import os, json, sys

MODEL_ID = "e7a64ff15fb1"
MODEL_NAME = "nemotron-3.5-lightning:30b"

# Windows Ollama paths
paths_to_check = [
    os.path.join(os.environ.get("USERPROFILE", ""), ".ollama", "models"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Ollama", "models"),
    "C:/Users/Garrett/.ollama/models",
    "D:/OllamaModels",
    "G:/",
    "G:/models",
    "G:/ollama",
    "G:/Ollama",
]

print("Searching for Ollama models and blobs...")
print(f"Target model: {MODEL_NAME} ({MODEL_ID})")
print()

# Check manifests first to find the layer digest
manifest_found = False
for base in paths_to_check:
    manifest_dir = os.path.join(base, "manifests") if not base.endswith("/") else os.path.join(base, "manifests")
    if os.path.isdir(manifest_dir):
        print(f"Manifest dir exists: {manifest_dir}")
        for root, dirs, files in os.walk(manifest_dir):
            for f in files:
                if "nemo" in f.lower() or "nemotron" in f.lower():
                    fp = os.path.join(root, f)
                    print(f"  Manifest: {fp}")
                    try:
                        with open(fp, "r") as mf:
                            data = json.load(mf)
                        for layer in data.get("layers", []):
                            if layer.get("mediaType", "").endswith("model"):
                                digest = layer.get("digest", "")
                                size = layer.get("size", 0)
                                print(f"    Model layer digest: {digest} ({size/1e9:.2f} GB)")
                                manifest_found = True
                    except Exception as e:
                        print(f"    Error reading manifest: {e}")

if not manifest_found:
    print("No manifests found for nemotron. Trying general blob scan...")

# Now scan for blobs
print("\nScanning for blob files...")
for base in paths_to_check:
    blobs_dir = os.path.join(base, "blobs") if not base.endswith("/") else os.path.join(base, "blobs")
    if os.path.isdir(blobs_dir):
        print(f"Blobs dir exists: {blobs_dir}")
        for root, dirs, files in os.walk(blobs_dir):
            for f in files:
                fp = os.path.join(root, f)
                sz = os.path.getsize(fp)
                if sz > 20e9:  # > 20 GB
                    print(f"  Large blob: {fp} {sz/1e9:.2f} GB")
                # Also check if filename contains model id
                if MODEL_ID in f:
                    print(f"  *** MATCH *** {fp} {sz/1e9:.2f} GB")

# Also do a quick size-based scan on G: drive
if os.path.exists("G:/"):
    print("\nScanning G:/ for large files (>10GB)...")
    count = 0
    for root, dirs, files in os.walk("G:/"):
        # Skip system directories
        dirs[:] = [d for d in dirs if d.lower() not in ("$recycle.bin", "system volume information", "windows")]
        for f in files:
            try:
                fp = os.path.join(root, f)
                sz = os.path.getsize(fp)
                if sz > 10e9:
                    print(f"  {fp} {sz/1e9:.2f} GB")
                    count += 1
                    if count >= 20:
                        print("  (showing first 20 large files)")
                        break
            except:
                pass
        if count >= 20:
            break

print("\nDone.")
