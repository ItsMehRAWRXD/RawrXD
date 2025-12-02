using LLama;
using Microsoft.Extensions.Logging;

namespace RawrXD.Ollama.Services;

/// <summary>
/// Manages LoRA adapters for efficient model fine-tuning without modifying base weights.
/// Allows multiple adapters to be composed and applied dynamically.
/// </summary>
public sealed class LoRAAdapterService : IAsyncDisposable
{
    private readonly string _adapterDirectory;
    private readonly ILogger<LoRAAdapterService>? _logger;
    private readonly Dictionary<string, LoRAAdapter> _loadedAdapters = new();
    private readonly object _adapterLock = new();

    public IReadOnlyDictionary<string, LoRAAdapter> LoadedAdapters => _loadedAdapters.AsReadOnly();

    public LoRAAdapterService(string? adapterDirectory = null, ILogger<LoRAAdapterService>? logger = null)
    {
        _adapterDirectory = adapterDirectory ?? Path.Combine(AppContext.BaseDirectory, "adapters");
        _logger = logger;
        EnsureAdapterDirectoryExists();
    }

    private void EnsureAdapterDirectoryExists()
    {
        if (!Directory.Exists(_adapterDirectory))
        {
            Directory.CreateDirectory(_adapterDirectory);
            _logger?.LogInformation("📁 Created LoRA adapter directory: {AdapterDir}", _adapterDirectory);
        }
    }

    /// <summary>
    /// Load a LoRA adapter from disk.
    /// </summary>
    public async Task<LoRAAdapter> LoadAdapterAsync(string adapterName, string adapterPath)
    {
        lock (_adapterLock)
        {
            if (_loadedAdapters.ContainsKey(adapterName))
            {
                _logger?.LogInformation("✓ LoRA adapter already loaded: {AdapterName}", adapterName);
                return _loadedAdapters[adapterName];
            }
        }

        try
        {
            if (!File.Exists(adapterPath))
            {
                throw new FileNotFoundException($"LoRA adapter not found: {adapterPath}");
            }

            _logger?.LogInformation("📥 Loading LoRA adapter: {AdapterName} from {Path}", adapterName, adapterPath);
            var fileInfo = new FileInfo(adapterPath);
            _logger?.LogInformation("   Adapter size: {SizeMB} MB", Math.Round(fileInfo.Length / (1024.0 * 1024.0), 2));

            // Load adapter metadata
            var adapter = new LoRAAdapter
            {
                Name = adapterName,
                Path = adapterPath,
                LoadedAt = DateTime.UtcNow,
                FileSize = fileInfo.Length
            };

            lock (_adapterLock)
            {
                _loadedAdapters[adapterName] = adapter;
            }

            _logger?.LogInformation("✅ LoRA adapter loaded: {AdapterName}", adapterName);
            return await Task.FromResult(adapter);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "❌ Failed to load LoRA adapter: {AdapterName}", adapterName);
            throw;
        }
    }

    /// <summary>
    /// Apply multiple LoRA adapters with different weights for composition.
    /// </summary>
    public LoRAComposition CreateComposition(string compositionName, Dictionary<string, float> adapterWeights)
    {
        lock (_adapterLock)
        {
            // Validate all adapters are loaded
            foreach (var adapterName in adapterWeights.Keys)
            {
                if (!_loadedAdapters.ContainsKey(adapterName))
                {
                    throw new InvalidOperationException($"LoRA adapter not loaded: {adapterName}");
                }
            }

            var composition = new LoRAComposition
            {
                Name = compositionName,
                AdapterWeights = new Dictionary<string, float>(adapterWeights),
                CreatedAt = DateTime.UtcNow
            };

            _logger?.LogInformation(
                "📦 Created LoRA composition: {CompositionName} with {AdapterCount} adapters",
                compositionName,
                adapterWeights.Count
            );

            return composition;
        }
    }

    /// <summary>
    /// Get all available adapters in the adapter directory.
    /// </summary>
    public async Task<List<string>> GetAvailableAdaptersAsync()
    {
        var adapterFiles = Directory.GetFiles(_adapterDirectory, "*.gguf", SearchOption.AllDirectories);
        var adapters = adapterFiles.Select(Path.GetFileNameWithoutExtension).ToList();
        
        _logger?.LogInformation("🔍 Found {AdapterCount} available LoRA adapters", adapters.Count);
        return await Task.FromResult(adapters);
    }

    /// <summary>
    /// Unload a LoRA adapter from memory.
    /// </summary>
    public async Task UnloadAdapterAsync(string adapterName)
    {
        lock (_adapterLock)
        {
            if (_loadedAdapters.Remove(adapterName))
            {
                _logger?.LogInformation("🗑️  Unloaded LoRA adapter: {AdapterName}", adapterName);
            }
        }
        await Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        lock (_adapterLock)
        {
            _loadedAdapters.Clear();
        }
        _logger?.LogInformation("🛑 LoRA adapter service disposed");
        await Task.CompletedTask;
    }
}

/// <summary>
/// Represents a loaded LoRA adapter.
/// </summary>
public class LoRAAdapter
{
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public DateTime LoadedAt { get; set; }
    public string? Description { get; set; }
    public Dictionary<string, string>? Metadata { get; set; }
}

/// <summary>
/// Represents a composition of multiple LoRA adapters with weights.
/// </summary>
public class LoRAComposition
{
    public string Name { get; set; } = string.Empty;
    public Dictionary<string, float> AdapterWeights { get; set; } = new();
    public DateTime CreatedAt { get; set; }
    public string? Description { get; set; }

    /// <summary>
    /// Get normalized weights (sum to 1.0 for blending).
    /// </summary>
    public Dictionary<string, float> GetNormalizedWeights()
    {
        var total = AdapterWeights.Values.Sum();
        if (total <= 0) return AdapterWeights;

        return AdapterWeights.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value / total
        );
    }
}
