#!/usr/bin/env python3
"""
RawrXD LlamaIndex Integration

This example shows how to use RawrXD with LlamaIndex for building
RAG (Retrieval Augmented Generation) applications.

Usage:
    python integration_llamaindex.py
    
Requirements:
    pip install llama-index llama-index-embeddings-openai
"""

import os
from llama_index.core import Settings, VectorStoreIndex, Document
from llama_index.core.node_parser import SentenceSplitter
from llama_index.llms.openai import OpenAI as LlamaOpenAI
from llama_index.embeddings.openai import OpenAIEmbedding

# Configure LlamaIndex to use RawrXD
rawrxd_url = os.getenv("RAWRXD_URL", "http://localhost:8080")

# Initialize LLM
Settings.llm = LlamaOpenAI(
    model="llama-2-7b-chat",
    api_base=rawrxd_url,
    api_key="not-needed",
    temperature=0.7
)

# Initialize embeddings
Settings.embed_model = OpenAIEmbedding(
    model="llama-2-7b",
    api_base=rawrxd_url,
    api_key="not-needed"
)

# Configure text splitter
Settings.text_splitter = SentenceSplitter(chunk_size=512, chunk_overlap=50)


def basic_rag_example():
    """Basic RAG example."""
    print("=== Basic RAG Example ===\n")
    
    # Create documents
    documents = [
        Document(text="""
            RawrXD is a high-performance LLM inference framework written in C++.
            It supports multiple backends including CUDA, Vulkan, and CPU.
            RawrXD features Flash Attention, speculative decoding, and continuous batching.
        """),
        Document(text="""
            Flash Attention is an efficient attention algorithm that reduces
            memory usage from O(N²) to O(N). It achieves 2-4x speedup over
            standard attention implementations.
        """),
        Document(text="""
            Speculative decoding uses a small draft model to generate candidate
            tokens, which are then verified by the larger target model.
            This can achieve 2-3x speedup in inference.
        """)
    ]
    
    # Create index
    print("Creating index...")
    index = VectorStoreIndex.from_documents(documents)
    
    # Create query engine
    query_engine = index.as_query_engine()
    
    # Query
    print("Querying: What is Flash Attention?\n")
    response = query_engine.query("What is Flash Attention?")
    
    print(f"Response: {response}\n")
    print(f"Source nodes: {len(response.source_nodes)}\n")


def chat_engine_example():
    """Chat engine with memory."""
    print("=== Chat Engine Example ===\n")
    
    # Create documents
    documents = [
        Document(text="RawrXD supports multiple model formats including GGUF, ONNX, and Safetensors."),
        Document(text="RawrXD can be deployed on-premises or in the cloud."),
        Document(text="RawrXD provides OpenAI-compatible API endpoints.")
    ]
    
    # Create index
    index = VectorStoreIndex.from_documents(documents)
    
    # Create chat engine with memory
    chat_engine = index.as_chat_engine(
        chat_mode="context",
        verbose=True
    )
    
    # Chat
    print("User: What model formats does RawrXD support?")
    response = chat_engine.chat("What model formats does RawrXD support?")
    print(f"Assistant: {response}\n")
    
    print("User: Can it run in the cloud?")
    response = chat_engine.chat("Can it run in the cloud?")
    print(f"Assistant: {response}\n")


def custom_prompt_example():
    """Custom prompt template."""
    print("=== Custom Prompt Example ===\n")
    
    from llama_index.core import PromptTemplate
    
    # Define custom prompt
    qa_prompt = PromptTemplate(
        """Context information is below.
---------------------
{context_str}
---------------------
Given the context information and not prior knowledge, 
answer the question: {query_str}

If the answer is not in the context, say "I don't know".

Answer:"""
    )
    
    # Create documents
    documents = [
        Document(text="RawrXD achieves 547 TPS on 7B models with 28ms P50 latency.")
    ]
    
    # Create index
    index = VectorStoreIndex.from_documents(documents)
    
    # Create query engine with custom prompt
    query_engine = index.as_query_engine(
        text_qa_template=qa_prompt
    )
    
    # Query
    response = query_engine.query("What is RawrXD's performance?")
    print(f"Response: {response}\n")


def streaming_example():
    """Streaming responses."""
    print("=== Streaming Example ===\n")
    
    documents = [
        Document(text="RawrXD is built with modern C++20 for maximum performance.")
    ]
    
    index = VectorStoreIndex.from_documents(documents)
    query_engine = index.as_query_engine(streaming=True)
    
    print("Query: Tell me about RawrXD\n")
    print("Response: ", end="", flush=True)
    
    response = query_engine.query("Tell me about RawrXD")
    for text in response.response_gen:
        print(text, end="", flush=True)
    print("\n")


def multi_document_example():
    """Multi-document RAG."""
    print("=== Multi-Document RAG Example ===\n")
    
    # Simulate multiple documents
    documents = [
        Document(text="RawrXD v1.0 was released in 2024.", metadata={"source": "release_notes"}),
        Document(text="RawrXD supports distributed inference across multiple GPUs.", metadata={"source": "docs"}),
        Document(text="RawrXD includes comprehensive monitoring with Prometheus.", metadata={"source": "docs"}),
        Document(text="RawrXD provides client SDKs for Python, Rust, Go, and Node.js.", metadata={"source": "readme"})
    ]
    
    # Create index
    index = VectorStoreIndex.from_documents(documents)
    
    # Query
    query_engine = index.as_query_engine()
    
    queries = [
        "What features does RawrXD have?",
        "How can I monitor RawrXD?",
        "What languages are supported?"
    ]
    
    for query in queries:
        print(f"Query: {query}")
        response = query_engine.query(query)
        print(f"Response: {response}\n")


def agent_example():
    """Agent with tools (simplified)."""
    print("=== Agent Example ===\n")
    
    print("LlamaIndex agents can use RawrXD as the LLM backend.")
    print("Agents can:")
    print("  - Query documents")
    print("  - Use tools")
    print("  - Make decisions")
    print("  - Execute multi-step tasks")
    print("\nSee LlamaIndex documentation for full agent examples.\n")


def main():
    """Run all examples."""
    print("RawrXD LlamaIndex Integration Demo")
    print("=" * 50)
    print(f"Server: {rawrxd_url}")
    print("=" * 50)
    
    try:
        basic_rag_example()
        chat_engine_example()
        custom_prompt_example()
        streaming_example()
        multi_document_example()
        agent_example()
        
        print("=" * 50)
        print("All examples completed!")
        print("=" * 50)
        
    except Exception as e:
        print(f"\nError: {e}")
        print("\nMake sure:")
        print("1. RawrXD server is running")
        print("2. Required packages are installed:")
        print("   pip install llama-index llama-index-embeddings-openai")


if __name__ == "__main__":
    main()
