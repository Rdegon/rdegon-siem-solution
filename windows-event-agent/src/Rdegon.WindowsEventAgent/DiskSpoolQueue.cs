using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Rdegon.WindowsEventAgent;

public sealed class DiskSpoolQueue
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly string _spoolDirectory;

    public DiskSpoolQueue(IOptions<AgentOptions> options)
    {
        _spoolDirectory = ResolveSpoolDirectory(options.Value);
        Directory.CreateDirectory(_spoolDirectory);
    }

    public async Task EnqueueAsync(string routePath, IReadOnlyCollection<Dictionary<string, object?>> events, CancellationToken cancellationToken)
    {
        var envelope = new SpoolEnvelope
        {
            RoutePath = NormalizeRoutePath(routePath),
            Events = events.ToList()
        };

        var fileName = $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.json";
        var fullPath = Path.Combine(_spoolDirectory, fileName);

        await using var stream = File.Create(fullPath);
        await JsonSerializer.SerializeAsync(stream, envelope, SerializerOptions, cancellationToken);
    }

    public async Task<IReadOnlyList<QueuedBatch>> GetPendingAsync(CancellationToken cancellationToken)
    {
        var results = new List<QueuedBatch>();
        foreach (var path in Directory.EnumerateFiles(_spoolDirectory, "*.json").OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            await using var stream = File.OpenRead(path);
            var envelope = await JsonSerializer.DeserializeAsync<SpoolEnvelope>(stream, cancellationToken: cancellationToken);
            if (envelope is null || envelope.Events.Count == 0)
            {
                continue;
            }

            results.Add(new QueuedBatch(path, NormalizeRoutePath(envelope.RoutePath), envelope.Events));
        }

        return results;
    }

    public Task<int> CountPendingAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var count = Directory.EnumerateFiles(_spoolDirectory, "*.json").Count();
        return Task.FromResult(count);
    }

    public Task RemoveAsync(string filePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }

        return Task.CompletedTask;
    }

    public static string ResolveSpoolDirectory(AgentOptions options)
    {
        var expanded = Environment.ExpandEnvironmentVariables(options.SpoolDirectory ?? string.Empty).Trim();
        if (!string.IsNullOrWhiteSpace(expanded))
        {
            return expanded;
        }

        return Path.Combine(BookmarkStore.ResolveStateDirectory(options), "spool");
    }

    private static string NormalizeRoutePath(string routePath) =>
        string.IsNullOrWhiteSpace(routePath) ? "/ingest/windows/base" : "/" + routePath.Trim().Trim('/');
}

public sealed class QueuedBatch(string filePath, string routePath, List<Dictionary<string, object?>> events)
{
    public string FilePath { get; } = filePath;

    public string RoutePath { get; } = routePath;

    public List<Dictionary<string, object?>> Events { get; } = events;
}

public sealed class SpoolEnvelope
{
    public string RoutePath { get; set; } = "/ingest/windows/base";

    public List<Dictionary<string, object?>> Events { get; set; } = [];
}
