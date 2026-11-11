#!/usr/bin/env python3
"""
Embedding Example for RawrXD

This example demonstrates how to generate text embeddings
using the RawrXD API.

Requirements:
    pip install requests numpy

Usage:
    python embedding_example.py
"""

import requests
import numpy as np
from typing import List

# Configuration
API_BASE = "http://localhost:8080/v1"
MODEL = "llama-2-7b"


def get_embedding(text: str) -> List[float]:
    """
    Get embedding vector for text.
    
    Args:
        text: Input text to embed
    
    Returns:
        List of float values representing the embedding
    """
    response = requests.post(
        f"{API_BASE}/embeddings",
        json={
            "model": MODEL,
            "input": text
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        return data["data"][0]["embedding"]
    else:
        raise Exception(f"API Error: {response.status_code} - {response.text}")


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    a = np.array(a)
    b = np.array(b)
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


def main():
    print("RawrXD Embedding Example")
    print("=" * 50)
    
    # Example texts
    texts = [
        "The cat sat on the mat",
        "A feline rested on the rug",
        "The dog played in the park",
        "Machine learning is fascinating",
        "Artificial intelligence transforms industries"
    ]
    
    print("\nGenerating embeddings for sample texts...")
    embeddings = []
    for text in texts:
        print(f"  - '{text[:40]}...'")
        embedding = get_embedding(text)
        embeddings.append(embedding)
    
    print(f"\nEmbedding dimensions: {len(embeddings[0])}")
    
    # Calculate similarities
    print("\nSimilarity Matrix:")
    print("-" * 80)
    
    # Compare first text with others
    print(f"\nSimilarities to: '{texts[0]}'")
    for i, text in enumerate(texts[1:], 1):
        similarity = cosine_similarity(embeddings[0], embeddings[i])
        print(f"  vs '{text[:40]}...': {similarity:.4f}")
    
    # Find most similar pair
    print("\n\nMost Similar Pairs:")
    print("-" * 80)
    
    similarities = []
    for i in range(len(texts)):
        for j in range(i + 1, len(texts)):
            sim = cosine_similarity(embeddings[i], embeddings[j])
            similarities.append((sim, texts[i], texts[j]))
    
    # Sort by similarity
    similarities.sort(reverse=True)
    
    for sim, text1, text2 in similarities[:3]:
        print(f"\nSimilarity: {sim:.4f}")
        print(f"  1: {text1}")
        print(f"  2: {text2}")
    
    # Semantic search example
    print("\n\nSemantic Search Example:")
    print("-" * 80)
    
    query = "animals resting"
    query_embedding = get_embedding(query)
    
    print(f"Query: '{query}'")
    print("\nResults (sorted by relevance):")
    
    results = []
    for text, emb in zip(texts, embeddings):
        sim = cosine_similarity(query_embedding, emb)
        results.append((sim, text))
    
    results.sort(reverse=True)
    
    for sim, text in results:
        print(f"  [{sim:.4f}] {text}")


if __name__ == "__main__":
    main()
