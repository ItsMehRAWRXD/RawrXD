#!/usr/bin/env python3
"""
RawrXD LangChain Integration

This example shows how to use RawrXD with LangChain for building
LLM-powered applications.

Usage:
    python integration_langchain.py
    
Requirements:
    pip install langchain langchain-openai
"""

import os
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

# Configure LangChain to use RawrXD
rawrxd_url = os.getenv("RAWRXD_URL", "http://localhost:8080")

# Initialize LLM
llm = ChatOpenAI(
    model="llama-2-7b-chat",  # Your RawrXD model
    openai_api_base=rawrxd_url,
    openai_api_key="not-needed",
    temperature=0.7
)

# Initialize embeddings
embeddings = OpenAIEmbeddings(
    model="llama-2-7b",
    openai_api_base=rawrxd_url,
    openai_api_key="not-needed"
)


def basic_chat_example():
    """Basic chat with LangChain."""
    print("=== Basic Chat Example ===\n")
    
    messages = [
        SystemMessage(content="You are a helpful assistant."),
        HumanMessage(content="What is machine learning?")
    ]
    
    response = llm.invoke(messages)
    print(f"Response: {response.content}\n")


def prompt_template_example():
    """Using prompt templates."""
    print("=== Prompt Template Example ===\n")
    
    template = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant that explains {topic}."),
        ("human", "Explain {concept} in simple terms.")
    ])
    
    chain = template | llm | StrOutputParser()
    
    response = chain.invoke({
        "topic": "computer science",
        "concept": "recursion"
    })
    
    print(f"Response: {response}\n")


def streaming_example():
    """Streaming responses."""
    print("=== Streaming Example ===\n")
    
    messages = [
        HumanMessage(content="Write a haiku about programming")
    ]
    
    print("Response: ", end="", flush=True)
    for chunk in llm.stream(messages):
        print(chunk.content, end="", flush=True)
    print("\n")


def chain_example():
    """Building a simple chain."""
    print("=== Chain Example ===\n")
    
    # Create a simple translation chain
    template = """Translate the following text to {language}:
    
Text: {text}

Translation:"""
    
    prompt = ChatPromptTemplate.from_template(template)
    
    chain = (
        {"language": RunnablePassthrough(), "text": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )
    
    # Actually, let's fix the chain
    def format_input(inputs):
        return {
            "language": inputs["language"],
            "text": inputs["text"]
        }
    
    chain = (
        RunnablePassthrough()
        | prompt
        | llm
        | StrOutputParser()
    )
    
    response = chain.invoke({
        "language": "French",
        "text": "Hello, how are you today?"
    })
    
    print(f"Translation: {response}\n")


def embeddings_example():
    """Using embeddings."""
    print("=== Embeddings Example ===\n")
    
    texts = [
        "The quick brown fox",
        "jumps over the lazy dog",
        "Machine learning is fascinating"
    ]
    
    print("Generating embeddings...")
    vectors = embeddings.embed_documents(texts)
    
    for i, (text, vector) in enumerate(zip(texts, vectors)):
        print(f"Text {i+1}: {text}")
        print(f"  Dimension: {len(vector)}")
        print(f"  First 5 values: {vector[:5]}")
    
    print()


def rag_skeleton_example():
    """RAG (Retrieval Augmented Generation) skeleton."""
    print("=== RAG Skeleton Example ===\n")
    
    # This is a simplified RAG example
    # In production, you'd use a vector database like Chroma or Pinecone
    
    documents = [
        "RawrXD is a high-performance LLM inference framework.",
        "It supports Flash Attention and speculative decoding.",
        "RawrXD is compatible with the OpenAI API format."
    ]
    
    # Generate embeddings for documents
    doc_embeddings = embeddings.embed_documents(documents)
    
    # User query
    query = "What features does RawrXD support?"
    query_embedding = embeddings.embed_query(query)
    
    # Simple similarity search (cosine similarity)
    import numpy as np
    
    def cosine_similarity(a, b):
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
    
    similarities = [
        cosine_similarity(query_embedding, doc_emb)
        for doc_emb in doc_embeddings
    ]
    
    # Get most relevant document
    most_relevant_idx = np.argmax(similarities)
    context = documents[most_relevant_idx]
    
    print(f"Query: {query}")
    print(f"Retrieved context: {context}")
    
    # Generate response with context
    template = """Answer the question based on the context:

Context: {context}

Question: {question}

Answer:"""
    
    prompt = ChatPromptTemplate.from_template(template)
    chain = prompt | llm | StrOutputParser()
    
    response = chain.invoke({
        "context": context,
        "question": query
    })
    
    print(f"Response: {response}\n")


def agent_skeleton_example():
    """Agent skeleton (simplified)."""
    print("=== Agent Skeleton Example ===\n")
    
    # Note: Full agent implementation requires additional tools
    # This shows the basic concept
    
    print("Agent would use tools like:")
    print("  - Search")
    print("  - Calculator")
    print("  - Code execution")
    print("\nRawrXD can power the LLM backend for agents.\n")


def main():
    """Run all examples."""
    print("RawrXD LangChain Integration Demo")
    print("=" * 50)
    print(f"Server: {rawrxd_url}")
    print("=" * 50)
    
    try:
        basic_chat_example()
        prompt_template_example()
        streaming_example()
        chain_example()
        embeddings_example()
        rag_skeleton_example()
        agent_skeleton_example()
        
        print("=" * 50)
        print("All examples completed!")
        print("=" * 50)
        
    except Exception as e:
        print(f"\nError: {e}")
        print("\nMake sure:")
        print("1. RawrXD server is running")
        print("2. Required packages are installed:")
        print("   pip install langchain langchain-openai")


if __name__ == "__main__":
    main()
