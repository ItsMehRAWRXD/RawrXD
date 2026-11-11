// RawrXD Go Client SDK
//
// A simple, efficient client for interacting with RawrXD LLM inference servers.
// Compatible with OpenAI API format.
//
// Example usage:
//     client := rawrxd.NewClient("http://localhost:8080", nil)
//     response, err := client.Complete("Hello, world!")
//     fmt.Println(response.Text)

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client represents a RawrXD API client
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new RawrXD client
func NewClient(baseURL string, apiKey string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// SetTimeout sets the HTTP client timeout
func (c *Client) SetTimeout(timeout time.Duration) {
	c.HTTPClient.Timeout = timeout
}

// CompletionRequest represents a completion request
type CompletionRequest struct {
	Model             string   `json:"model,omitempty"`
	Prompt            string   `json:"prompt"`
	MaxTokens         int      `json:"max_tokens,omitempty"`
	Temperature       float64  `json:"temperature,omitempty"`
	TopP              float64  `json:"top_p,omitempty"`
	TopK              int      `json:"top_k,omitempty"`
	RepetitionPenalty float64  `json:"repetition_penalty,omitempty"`
	Stream            bool     `json:"stream,omitempty"`
	Stop              []string `json:"stop,omitempty"`
	Seed              int      `json:"seed,omitempty"`
}

// CompletionResponse represents a completion response
type CompletionResponse struct {
	ID      string             `json:"id"`
	Object  string             `json:"object"`
	Created int64              `json:"created"`
	Model   string             `json:"model"`
	Choices []CompletionChoice `json:"choices"`
	Usage   Usage              `json:"usage"`
}

// CompletionChoice represents a completion choice
type CompletionChoice struct {
	Text         string `json:"text"`
	Index        int    `json:"index"`
	FinishReason string `json:"finish_reason"`
}

// Usage represents token usage
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatMessage represents a chat message
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest represents a chat completion request
type ChatRequest struct {
	Model       string        `json:"model,omitempty"`
	Messages    []ChatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
	TopP        float64       `json:"top_p,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
}

// ChatResponse represents a chat completion response
type ChatResponse struct {
	ID      string       `json:"id"`
	Object  string       `json:"object"`
	Created int64        `json:"created"`
	Model   string       `json:"model"`
	Choices []ChatChoice `json:"choices"`
	Usage   Usage        `json:"usage"`
}

// ChatChoice represents a chat choice
type ChatChoice struct {
	Index        int         `json:"index"`
	Message      ChatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

// EmbeddingRequest represents an embedding request
type EmbeddingRequest struct {
	Model          string `json:"model,omitempty"`
	Input          string `json:"input"`
	EncodingFormat string `json:"encoding_format,omitempty"`
}

// EmbeddingResponse represents an embedding response
type EmbeddingResponse struct {
	Object string          `json:"object"`
	Data   []EmbeddingData `json:"data"`
	Model  string          `json:"model"`
	Usage  Usage           `json:"usage"`
}

// EmbeddingData represents embedding data
type EmbeddingData struct {
	Object    string    `json:"object"`
	Embedding []float64 `json:"embedding"`
	Index     int       `json:"index"`
}

// ModelInfo represents model information
type ModelInfo struct {
	ID       string `json:"id"`
	Object   string `json:"object"`
	Created  int64  `json:"created"`
	OwnedBy  string `json:"owned_by"`
}

// ModelsResponse represents the models list response
type ModelsResponse struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

// APIError represents an API error
type APIError struct {
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (%s): %s", e.Code, e.Message)
}

// doRequest performs an HTTP request
func (c *Client) doRequest(method, endpoint string, body interface{}) (*http.Response, error) {
	url := c.BaseURL + "/" + endpoint

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	return c.HTTPClient.Do(req)
}

// Complete generates a text completion
func (c *Client) Complete(request CompletionRequest) (*CompletionResponse, error) {
	resp, err := c.doRequest("POST", "v1/completions", request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{Message: string(body), Code: "http_error"}
	}

	var completion CompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&completion); err != nil {
		return nil, err
	}

	return &completion, nil
}

// CompleteSimple is a simple completion helper
func (c *Client) CompleteSimple(prompt string) (string, error) {
	request := CompletionRequest{
		Prompt:      prompt,
		MaxTokens:   256,
		Temperature: 0.7,
		TopP:        0.9,
	}

	response, err := c.Complete(request)
	if err != nil {
		return "", err
	}

	if len(response.Choices) > 0 {
		return response.Choices[0].Text, nil
	}

	return "", nil
}

// Chat generates a chat completion
func (c *Client) Chat(request ChatRequest) (*ChatResponse, error) {
	resp, err := c.doRequest("POST", "v1/chat/completions", request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{Message: string(body), Code: "http_error"}
	}

	var chatResponse ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResponse); err != nil {
		return nil, err
	}

	return &chatResponse, nil
}

// ChatSimple is a simple chat helper
func (c *Client) ChatSimple(messages []ChatMessage) (string, error) {
	request := ChatRequest{
		Messages:    messages,
		MaxTokens:   256,
		Temperature: 0.7,
		TopP:        0.9,
	}

	response, err := c.Chat(request)
	if err != nil {
		return "", err
	}

	if len(response.Choices) > 0 {
		return response.Choices[0].Message.Content, nil
	}

	return "", nil
}

// Embed generates embeddings
func (c *Client) Embed(request EmbeddingRequest) (*EmbeddingResponse, error) {
	resp, err := c.doRequest("POST", "v1/embeddings", request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{Message: string(body), Code: "http_error"}
	}

	var embedding EmbeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&embedding); err != nil {
		return nil, err
	}

	return &embedding, nil
}

// EmbedSimple is a simple embedding helper
func (c *Client) EmbedSimple(text string) ([]float64, error) {
	request := EmbeddingRequest{
		Input:          text,
		EncodingFormat: "float",
	}

	response, err := c.Embed(request)
	if err != nil {
		return nil, err
	}

	if len(response.Data) > 0 {
		return response.Data[0].Embedding, nil
	}

	return []float64{}, nil
}

// ListModels lists available models
func (c *Client) ListModels() ([]ModelInfo, error) {
	resp, err := c.doRequest("GET", "v1/models", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{Message: string(body), Code: "http_error"}
	}

	var models ModelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, err
	}

	return models.Data, nil
}

// Health checks server health
func (c *Client) Health() (*HealthResponse, error) {
	resp, err := c.doRequest("GET", "health", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{Message: string(body), Code: "health_check_failed"}
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, err
	}

	return &health, nil
}

func main() {
	// Create client
	client := NewClient("http://localhost:8080", "")

	// Check health
	health, err := client.Health()
	if err != nil {
		fmt.Printf("Health check failed: %v\n", err)
	} else {
		fmt.Printf("Server status: %s\n", health.Status)
	}

	// Simple completion
	completion, err := client.CompleteSimple("The capital of France is")
	if err != nil {
		fmt.Printf("Completion failed: %v\n", err)
	} else {
		fmt.Printf("Completion: %s\n", completion)
	}

	// Chat completion
	messages := []ChatMessage{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: "What is Go?"},
	}

	chatResponse, err := client.ChatSimple(messages)
	if err != nil {
		fmt.Printf("Chat failed: %v\n", err)
	} else {
		fmt.Printf("Chat response: %s\n", chatResponse)
	}

	// Embeddings
	embedding, err := client.EmbedSimple("Hello, world!")
	if err != nil {
		fmt.Printf("Embedding failed: %v\n", err)
	} else {
		fmt.Printf("Embedding dimension: %d\n", len(embedding))
	}

	// List models
	models, err := client.ListModels()
	if err != nil {
		fmt.Printf("List models failed: %v\n", err)
	} else {
		fmt.Println("Available models:")
		for _, model := range models {
			fmt.Printf("  - %s\n", model.ID)
		}
	}
}
