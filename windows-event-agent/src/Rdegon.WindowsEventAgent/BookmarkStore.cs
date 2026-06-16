using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Rdegon.WindowsEventAgent;

public sealed class BookmarkStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly string _bookmarkPath;

    public BookmarkStore(IOptions<AgentOptions> options)
    {
        var stateDirectory = ResolveStateDirectory(options.Value);
        Directory.CreateDirectory(stateDirectory);
        _bookmarkPath = Path.Combine(stateDirectory, "bookmarks.json");
    }

    public async Task<long> GetLastRecordIdAsync(string channelName, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateAsync(cancellationToken);
            return state.TryGetValue(channelName, out var recordId) ? recordId : 0L;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task SaveLastRecordIdAsync(string channelName, long recordId, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            var state = await LoadStateAsync(cancellationToken);
            state[channelName] = recordId;
            await using var stream = File.Create(_bookmarkPath);
            await JsonSerializer.SerializeAsync(stream, state, SerializerOptions, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public static string ResolveStateDirectory(AgentOptions options)
    {
        var expanded = Environment.ExpandEnvironmentVariables(options.StateDirectory ?? string.Empty).Trim();
        if (!string.IsNullOrWhiteSpace(expanded))
        {
            return expanded;
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "RdegonSIEM",
            "WindowsEventAgent");
    }

    private async Task<Dictionary<string, long>> LoadStateAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_bookmarkPath))
        {
            return new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        }

        await using var stream = File.OpenRead(_bookmarkPath);
        var payload = await JsonSerializer.DeserializeAsync<Dictionary<string, long>>(stream, cancellationToken: cancellationToken);
        return payload ?? new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
    }
}
