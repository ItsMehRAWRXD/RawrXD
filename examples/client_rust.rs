// RawrXD Rust Client SDK
// 
// A simple, efficient client for interacting with RawrXD LLM inference servers.
// Compatible with OpenAI API format.
//
// Example usage:
//     let client = RawrXDClient::new("http://localhost:8080", None);
//     let response = client.complete("Hello, world!").await?;
//     println!("{}", response.text);

use reqwest::{Client, Error as ReqwestError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// RawrXD API client
pub struct RawrXDClient {
    base_url: String,
    api_key: Option<String>,
    client: Client,
    timeout: Duration,
}

/// Completion request parameters
#[derive(Serialize)]
pub struct CompletionRequest {
    pub prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repetition_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
}

impl Default for CompletionRequest {
    fn default() -> Self {
        Self {
            prompt: String::new(),
            model: None,
            max_tokens: Some(256),
            temperature: Some(0.7),
            top_p: Some(0.9),
            top_k: Some(40),
            repetition_penalty: Some(1.0),
            stream: Some(false),
            stop: None,
            seed: None,
        }
    }
}

/// Completion response
#[derive(Deserialize, Debug)]
pub struct CompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<CompletionChoice>,
    pub usage: Usage,
}

#[derive(Deserialize, Debug)]
pub struct CompletionChoice {
    pub text: String,
    pub index: u32,
    pub finish_reason: String,
}

#[derive(Deserialize, Debug)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Chat message
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Chat request parameters
#[derive(Serialize)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

/// Chat response
#[derive(Deserialize, Debug)]
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
}

#[derive(Deserialize, Debug)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

/// Embedding request
#[derive(Serialize)]
pub struct EmbeddingRequest {
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding_format: Option<String>,
}

/// Embedding response
#[derive(Deserialize, Debug)]
pub struct EmbeddingResponse {
    pub object: String,
    pub data: Vec<EmbeddingData>,
    pub model: String,
    pub usage: Usage,
}

#[derive(Deserialize, Debug)]
pub struct EmbeddingData {
    pub object: String,
    pub embedding: Vec<f32>,
    pub index: u32,
}

/// Model information
#[derive(Deserialize, Debug)]
pub struct ModelInfo {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub owned_by: String,
}

/// Models list response
#[derive(Deserialize, Debug)]
pub struct ModelsResponse {
    pub object: String,
    pub data: Vec<ModelInfo>,
}

/// Health check response
#[derive(Deserialize, Debug)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
}

/// RawrXD error
#[derive(Debug)]
pub enum RawrXDError {
    HttpError(ReqwestError),
    ApiError { message: String, code: String },
    SerializationError(serde_json::Error),
}

impl std::fmt::Display for RawrXDError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawrXDError::HttpError(e) => write!(f, "HTTP error: {}", e),
            RawrXDError::ApiError { message, code } => {
                write!(f, "API error ({}): {}", code, message)
            }
            RawrXDError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for RawrXDError {}

impl From<ReqwestError> for RawrXDError {
    fn from(error: ReqwestError) -> Self {
        RawrXDError::HttpError(error)
    }
}

impl From<serde_json::Error> for RawrXDError {
    fn from(error: serde_json::Error) -> Self {
        RawrXDError::SerializationError(error)
    }
}

impl RawrXDClient {
    /// Create a new RawrXD client
    pub fn new(base_url: &str, api_key: Option<String>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            client: Client::new(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Set request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn build_request(&self, method: reqwest::Method, endpoint: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/{}", self.base_url, endpoint);
        let mut builder = self
            .client
            .request(method, &url)
            .timeout(self.timeout)
            .header("Content-Type", "application/json");

        if let Some(ref key) = self.api_key {
            builder = builder.header("Authorization", format!("Bearer {}", key));
        }

        builder
    }

    /// Generate text completion
    pub async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, RawrXDError> {
        let response = self
            .build_request(reqwest::Method::POST, "v1/completions")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(RawrXDError::ApiError {
                message: error_text,
                code: "api_error".to_string(),
            });
        }

        let completion: CompletionResponse = response.json().await?;
        Ok(completion)
    }

    /// Simple completion helper
    pub async fn complete_text(&self, prompt: &str) -> Result<String, RawrXDError> {
        let request = CompletionRequest {
            prompt: prompt.to_string(),
            ..Default::default()
        };

        let response = self.complete(request).await?;
        Ok(response.choices.into_iter().next().map(|c| c.text).unwrap_or_default())
    }

    /// Generate chat completion
    pub async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, RawrXDError> {
        let response = self
            .build_request(reqwest::Method::POST, "v1/chat/completions")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(RawrXDError::ApiError {
                message: error_text,
                code: "api_error".to_string(),
            });
        }

        let chat_response: ChatResponse = response.json().await?;
        Ok(chat_response)
    }

    /// Simple chat helper
    pub async fn chat_simple(&self, messages: Vec<ChatMessage>) -> Result<String, RawrXDError> {
        let request = ChatRequest {
            messages,
            model: None,
            max_tokens: Some(256),
            temperature: Some(0.7),
            top_p: Some(0.9),
            stream: Some(false),
        };

        let response = self.chat(request).await?;
        Ok(response.choices.into_iter().next().map(|c| c.message.content).unwrap_or_default())
    }

    /// Generate embeddings
    pub async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse, RawrXDError> {
        let response = self
            .build_request(reqwest::Method::POST, "v1/embeddings")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(RawrXDError::ApiError {
                message: error_text,
                code: "api_error".to_string(),
            });
        }

        let embedding: EmbeddingResponse = response.json().await?;
        Ok(embedding)
    }

    /// Simple embedding helper
    pub async fn embed_text(&self, text: &str) -> Result<Vec<f32>, RawrXDError> {
        let request = EmbeddingRequest {
            input: text.to_string(),
            model: None,
            encoding_format: Some("float".to_string()),
        };

        let response = self.embed(request).await?;
        Ok(response.data.into_iter().next().map(|d| d.embedding).unwrap_or_default())
    }

    /// List available models
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>, RawrXDError> {
        let response = self
            .build_request(reqwest::Method::GET, "v1/models")
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(RawrXDError::ApiError {
                message: error_text,
                code: "api_error".to_string(),
            });
        }

        let models: ModelsResponse = response.json().await?;
        Ok(models.data)
    }

    /// Health check
    pub async fn health(&self) -> Result<HealthResponse, RawrXDError> {
        let response = self
            .build_request(reqwest::Method::GET, "health")
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(RawrXDError::ApiError {
                message: error_text,
                code: "health_check_failed".to_string(),
            });
        }

        let health: HealthResponse = response.json().await?;
        Ok(health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = RawrXDClient::new("http://localhost:8080", None);
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[tokio::test]
    async fn test_completion_request_defaults() {
        let request = CompletionRequest::default();
        assert_eq!(request.max_tokens, Some(256));
        assert_eq!(request.temperature, Some(0.7));
    }
}

// Example usage
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client
    let client = RawrXDClient::new("http://localhost:8080", None);

    // Check health
    match client.health().await {
        Ok(health) => println!("Server status: {}", health.status),
        Err(e) => eprintln!("Health check failed: {}", e),
    }

    // Simple completion
    let response = client.complete_text("The capital of France is").await?;
    println!("Completion: {}", response);

    // Chat completion
    let messages = vec![
        ChatMessage {
            role: "system".to_string(),
            content: "You are a helpful assistant.".to_string(),
        },
        ChatMessage {
            role: "user".to_string(),
            content: "What is Rust?".to_string(),
        },
    ];

    let chat_response = client.chat_simple(messages).await?;
    println!("Chat response: {}", chat_response);

    // Embeddings
    let embedding = client.embed_text("Hello, world!").await?;
    println!("Embedding dimension: {}", embedding.len());

    // List models
    let models = client.list_models().await?;
    println!("Available models:");
    for model in models {
        println!("  - {}", model.id);
    }

    Ok(())
}
