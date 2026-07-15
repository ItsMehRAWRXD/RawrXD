#!/usr/bin/env python3
"""
RawrXD Python Client SDK

A simple, efficient client for interacting with RawrXD LLM inference servers.
Compatible with OpenAI API format.

Example usage:
    >>> from rawrxd import RawrXDClient
    >>> client = RawrXDClient("http://localhost:8080")
    >>> response = client.complete("Hello, world!")
    >>> print(response.text)
"""

import json
import requests
from typing import Optional, List, Dict, Any, Iterator, Union
from dataclasses import dataclass
from enum import Enum


class Priority(Enum):
    """Request priority levels."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class CompletionRequest:
    """Parameters for a completion request."""
    prompt: str
    model: Optional[str] = None
    max_tokens: int = 256
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 40
    repetition_penalty: float = 1.0
    stream: bool = False
    priority: Priority = Priority.NORMAL
    user_id: Optional[str] = None


@dataclass
class ChatMessage:
    """A chat message."""
    role: str  # "system", "user", "assistant"
    content: str


@dataclass
class ChatRequest:
    """Parameters for a chat completion request."""
    messages: List[ChatMessage]
    model: Optional[str] = None
    max_tokens: int = 256
    temperature: float = 0.7
    top_p: float = 0.9
    stream: bool = False
    priority: Priority = Priority.NORMAL


@dataclass
class CompletionResponse:
    """Response from a completion request."""
    text: str
    tokens_generated: int
    finish_reason: str
    model: str
    usage: Dict[str, int]


@dataclass
class EmbeddingResponse:
    """Response from an embedding request."""
    embedding: List[float]
    model: str


class RawrXDClient:
    """
    Client for RawrXD LLM inference server.
    
    Args:
        base_url: The URL of the RawrXD server (e.g., "http://localhost:8080")
        api_key: Optional API key for authentication
        timeout: Request timeout in seconds
    """
    
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = 60.0
    ):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"
    
    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        stream: bool = False
    ) -> Union[Dict, Iterator[str]]:
        """Make a request to the server."""
        url = f"{self.base_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        
        try:
            if stream:
                response = self.session.post(
                    url,
                    json=data,
                    headers=headers,
                    stream=True,
                    timeout=self.timeout
                )
                response.raise_for_status()
                return self._stream_response(response)
            else:
                response = self.session.request(
                    method,
                    url,
                    json=data,
                    headers=headers,
                    timeout=self.timeout
                )
                response.raise_for_status()
                return response.json()
        except requests.exceptions.RequestException as e:
            raise RawrXDError(f"Request failed: {e}")
    
    def _stream_response(self, response: requests.Response) -> Iterator[str]:
        """Stream response from server."""
        for line in response.iter_lines():
            if line:
                line = line.decode('utf-8')
                if line.startswith('data: '):
                    data = line[6:]
                    if data == '[DONE]':
                        break
                    try:
                        chunk = json.loads(data)
                        if 'choices' in chunk and chunk['choices']:
                            delta = chunk['choices'][0].get('delta', {})
                            if 'content' in delta:
                                yield delta['content']
                    except json.JSONDecodeError:
                        continue
    
    def complete(
        self,
        prompt: str,
        **kwargs
    ) -> CompletionResponse:
        """
        Generate a completion for the given prompt.
        
        Args:
            prompt: The prompt text
            **kwargs: Additional parameters (max_tokens, temperature, etc.)
        
        Returns:
            CompletionResponse with generated text
        """
        request = CompletionRequest(prompt=prompt, **kwargs)
        
        payload = {
            "prompt": request.prompt,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "top_p": request.top_p,
            "top_k": request.top_k,
            "repetition_penalty": request.repetition_penalty,
            "stream": request.stream
        }
        
        if request.model:
            payload["model"] = request.model
        
        response = self._request("POST", "/v1/completions", payload)
        
        return CompletionResponse(
            text=response['choices'][0]['text'],
            tokens_generated=response['choices'][0].get('index', 0),
            finish_reason=response['choices'][0].get('finish_reason', 'stop'),
            model=response.get('model', 'unknown'),
            usage=response.get('usage', {})
        )
    
    def complete_stream(
        self,
        prompt: str,
        **kwargs
    ) -> Iterator[str]:
        """
        Stream completion tokens as they are generated.
        
        Args:
            prompt: The prompt text
            **kwargs: Additional parameters
        
        Yields:
            Generated text tokens
        """
        request = CompletionRequest(prompt=prompt, stream=True, **kwargs)
        
        payload = {
            "prompt": request.prompt,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": True
        }
        
        if request.model:
            payload["model"] = request.model
        
        return self._request("POST", "/v1/completions", payload, stream=True)
    
    def chat(
        self,
        messages: List[ChatMessage],
        **kwargs
    ) -> CompletionResponse:
        """
        Generate a chat completion.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters
        
        Returns:
            CompletionResponse with assistant's response
        """
        request = ChatRequest(messages=messages, **kwargs)
        
        payload = {
            "messages": [
                {"role": msg.role, "content": msg.content}
                for msg in request.messages
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "top_p": request.top_p,
            "stream": request.stream
        }
        
        if request.model:
            payload["model"] = request.model
        
        response = self._request("POST", "/v1/chat/completions", payload)
        
        return CompletionResponse(
            text=response['choices'][0]['message']['content'],
            tokens_generated=response['choices'][0].get('index', 0),
            finish_reason=response['choices'][0].get('finish_reason', 'stop'),
            model=response.get('model', 'unknown'),
            usage=response.get('usage', {})
        )
    
    def chat_stream(
        self,
        messages: List[ChatMessage],
        **kwargs
    ) -> Iterator[str]:
        """
        Stream chat completion tokens.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters
        
        Yields:
            Generated text tokens
        """
        request = ChatRequest(messages=messages, stream=True, **kwargs)
        
        payload = {
            "messages": [
                {"role": msg.role, "content": msg.content}
                for msg in request.messages
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": True
        }
        
        if request.model:
            payload["model"] = request.model
        
        return self._request("POST", "/v1/chat/completions", payload, stream=True)
    
    def embed(
        self,
        text: Union[str, List[str]],
        model: Optional[str] = None
    ) -> Union[EmbeddingResponse, List[EmbeddingResponse]]:
        """
        Generate embeddings for text.
        
        Args:
            text: Text or list of texts to embed
            model: Model to use for embeddings
        
        Returns:
            EmbeddingResponse or list of responses
        """
        is_single = isinstance(text, str)
        texts = [text] if is_single else text
        
        payload = {
            "input": texts
        }
        
        if model:
            payload["model"] = model
        
        response = self._request("POST", "/v1/embeddings", payload)
        
        embeddings = [
            EmbeddingResponse(
                embedding=item['embedding'],
                model=response.get('model', 'unknown')
            )
            for item in response['data']
        ]
        
        return embeddings[0] if is_single else embeddings
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List available models.
        
        Returns:
            List of model information dictionaries
        """
        response = self._request("GET", "/v1/models")
        return response.get('data', [])
    
    def health(self) -> Dict[str, Any]:
        """
        Check server health.
        
        Returns:
            Health status dictionary
        """
        return self._request("GET", "/health")
    
    def close(self):
        """Close the client session."""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class RawrXDError(Exception):
    """Exception raised for RawrXD client errors."""
    pass


# Convenience functions

def create_client(base_url: str, **kwargs) -> RawrXDClient:
    """Create a new RawrXD client."""
    return RawrXDClient(base_url, **kwargs)


def complete(prompt: str, base_url: str = "http://localhost:8080", **kwargs) -> str:
    """Quick completion function."""
    with create_client(base_url) as client:
        response = client.complete(prompt, **kwargs)
        return response.text


def chat(messages: List[Dict[str, str]], base_url: str = "http://localhost:8080", **kwargs) -> str:
    """Quick chat function."""
    chat_messages = [ChatMessage(**msg) for msg in messages]
    with create_client(base_url) as client:
        response = client.chat(chat_messages, **kwargs)
        return response.text


if __name__ == "__main__":
    # Example usage
    client = RawrXDClient("http://localhost:8080")
    
    # Simple completion
    print("=== Completion ===")
    response = client.complete("The capital of France is")
    print(response.text)
    
    # Streaming completion
    print("\n=== Streaming ===")
    for token in client.complete_stream("Count to 5: "):
        print(token, end='', flush=True)
    print()
    
    # Chat
    print("\n=== Chat ===")
    messages = [
        ChatMessage(role="system", content="You are a helpful assistant."),
        ChatMessage(role="user", content="What is machine learning?")
    ]
    response = client.chat(messages)
    print(response.text)
    
    # Embeddings
    print("\n=== Embeddings ===")
    embedding = client.embed("Hello, world!")
    print(f"Embedding dimension: {len(embedding.embedding)}")
    
    client.close()
