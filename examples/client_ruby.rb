# RawrXD Ruby Client SDK
#
# A simple, efficient client for interacting with RawrXD LLM inference servers.
# Compatible with OpenAI API format.
#
# Example usage:
#     client = RawrXDClient.new('http://localhost:8080')
#     response = client.complete('Hello, world!')
#     puts response[:text]

require 'net/http'
require 'json'
require 'uri'

# RawrXD API client
class RawrXDClient
  # Create a new RawrXD client
  #
  # @param base_url [String] Server URL
  # @param api_key [String, nil] API key for authentication
  # @param timeout [Integer] Request timeout in seconds
  def initialize(base_url, api_key = nil, timeout = 60)
    @base_url = base_url.chomp('/')
    @api_key = api_key
    @timeout = timeout
  end

  # Generate text completion
  #
  # @param prompt [String] Input prompt
  # @param model [String, nil] Model identifier
  # @param max_tokens [Integer] Maximum tokens to generate
  # @param temperature [Float] Sampling temperature
  # @param top_p [Float] Nucleus sampling threshold
  # @param top_k [Integer] Top-k sampling limit
  # @param repetition_penalty [Float] Repetition penalty
  # @param stream [Boolean] Stream response
  # @param stop [Array<String>, nil] Stop sequences
  # @param seed [Integer, nil] Random seed
  # @return [Hash] Completion response
  def complete(
    prompt,
    model: nil,
    max_tokens: 256,
    temperature: 0.7,
    top_p: 0.9,
    top_k: 40,
    repetition_penalty: 1.0,
    stream: false,
    stop: nil,
    seed: nil
  )
    request_body = {
      prompt: prompt,
      model: model,
      max_tokens: max_tokens,
      temperature: temperature,
      top_p: top_p,
      top_k: top_k,
      repetition_penalty: repetition_penalty,
      stream: stream,
      stop: stop,
      seed: seed
    }.compact

    post('/v1/completions', request_body)
  end

  # Simple completion helper
  #
  # @param prompt [String] Input prompt
  # @param options [Hash] Additional options
  # @return [String] Generated text
  def complete_simple(prompt, **options)
    response = complete(prompt, **options)
    response.dig(:choices, 0, :text).to_s
  end

  # Generate chat completion
  #
  # @param messages [Array<Hash>] Chat messages
  # @param model [String, nil] Model identifier
  # @param max_tokens [Integer] Maximum tokens to generate
  # @param temperature [Float] Sampling temperature
  # @param top_p [Float] Nucleus sampling threshold
  # @param stream [Boolean] Stream response
  # @return [Hash] Chat response
  def chat(
    messages,
    model: nil,
    max_tokens: 256,
    temperature: 0.7,
    top_p: 0.9,
    stream: false
  )
    request_body = {
      messages: messages,
      model: model,
      max_tokens: max_tokens,
      temperature: temperature,
      top_p: top_p,
      stream: stream
    }.compact

    post('/v1/chat/completions', request_body)
  end

  # Simple chat helper
  #
  # @param messages [Array<Hash>] Chat messages
  # @param options [Hash] Additional options
  # @return [String] Assistant's response
  def chat_simple(messages, **options)
    response = chat(messages, **options)
    response.dig(:choices, 0, :message, :content).to_s
  end

  # Generate embeddings
  #
  # @param input [String] Text to embed
  # @param model [String, nil] Model identifier
  # @param encoding_format [String] Encoding format
  # @return [Hash] Embedding response
  def embed(input, model: nil, encoding_format: 'float')
    request_body = {
      input: input,
      model: model,
      encoding_format: encoding_format
    }.compact

    post('/v1/embeddings', request_body)
  end

  # Simple embedding helper
  #
  # @param text [String] Text to embed
  # @param options [Hash] Additional options
  # @return [Array<Float>] Embedding vector
  def embed_simple(text, **options)
    response = embed(text, **options)
    response.dig(:data, 0, :embedding).to_a
  end

  # List available models
  #
  # @return [Array<Hash>] List of models
  def list_models
    response = get('/v1/models')
    response[:data].to_a
  end

  # Check server health
  #
  # @return [Hash] Health status
  def health
    get('/health')
  end

  private

  def get(endpoint)
    uri = URI.parse("#{@base_url}#{endpoint}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.read_timeout = @timeout

    request = Net::HTTP::Get.new(uri.request_uri)
    request['Content-Type'] = 'application/json'
    request['Authorization'] = "Bearer #{@api_key}" if @api_key

    response = http.request(request)
    handle_response(response)
  end

  def post(endpoint, body)
    uri = URI.parse("#{@base_url}#{endpoint}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.read_timeout = @timeout

    request = Net::HTTP::Post.new(uri.request_uri)
    request['Content-Type'] = 'application/json'
    request['Authorization'] = "Bearer #{@api_key}" if @api_key
    request.body = body.to_json

    response = http.request(request)
    handle_response(response)
  end

  def handle_response(response)
    case response.code.to_i
    when 200..299
      JSON.parse(response.body, symbolize_names: true)
    when 400
      raise RawrXDError, "Bad request: #{response.body}"
    when 401
      raise RawrXDError, "Unauthorized: Invalid API key"
    when 429
      raise RawrXDError, "Rate limited"
    when 500..599
      raise RawrXDError, "Server error: #{response.body}"
    else
      raise RawrXDError, "Unexpected error: #{response.code}"
    end
  end
end

# RawrXD error class
class RawrXDError < StandardError; end

# Example usage
if __FILE__ == $0
  # Create client
  client = RawrXDClient.new('http://localhost:8080')

  # Check health
  begin
    health = client.health
    puts "Server status: #{health[:status]}"
  rescue RawrXDError => e
    puts "Health check failed: #{e.message}"
  end

  # Simple completion
  begin
    completion = client.complete_simple('The capital of France is')
    puts "Completion: #{completion}"
  rescue RawrXDError => e
    puts "Completion failed: #{e.message}"
  end

  # Chat completion
  begin
    messages = [
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user', content: 'What is Ruby?' }
    ]
    chat_response = client.chat_simple(messages)
    puts "Chat response: #{chat_response}"
  rescue RawrXDError => e
    puts "Chat failed: #{e.message}"
  end

  # Embeddings
  begin
    embedding = client.embed_simple('Hello, world!')
    puts "Embedding dimension: #{embedding.length}"
  rescue RawrXDError => e
    puts "Embedding failed: #{e.message}"
  end

  # List models
  begin
    models = client.list_models
    puts 'Available models:'
    models.each do |model|
      puts "  - #{model[:id]}"
    end
  rescue RawrXDError => e
    puts "List models failed: #{e.message}"
  end
end
