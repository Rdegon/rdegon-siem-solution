using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace Rdegon.WindowsEventAgent;

public sealed class IngestHttpClient
{
    private readonly HttpClient _httpClient;
    private readonly AgentOptions _options;

    public IngestHttpClient(HttpClient httpClient, IOptions<AgentOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
    }

    public async Task SendBatchAsync(string routePath, IReadOnlyCollection<Dictionary<string, object?>> events, CancellationToken cancellationToken)
    {
        if (events.Count == 0)
        {
            return;
        }

        var normalizedRoutePath = NormalizeRoutePath(routePath);
        var maxSendBatch = Math.Max(1, _options.MaxSendBatch);

        foreach (var batch in Split(events, maxSendBatch))
        {
            using var response = await _httpClient.PostAsJsonAsync(normalizedRoutePath, batch, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                continue;
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException($"Ingest rejected {normalizedRoutePath}: {(int)response.StatusCode} {response.ReasonPhrase} {body}".Trim());
        }
    }

    private static IEnumerable<IReadOnlyList<Dictionary<string, object?>>> Split(IReadOnlyCollection<Dictionary<string, object?>> events, int size)
    {
        var buffer = new List<Dictionary<string, object?>>(size);
        foreach (var item in events)
        {
            buffer.Add(item);
            if (buffer.Count < size)
            {
                continue;
            }

            yield return buffer.ToArray();
            buffer.Clear();
        }

        if (buffer.Count > 0)
        {
            yield return buffer.ToArray();
        }
    }

    private static string NormalizeRoutePath(string routePath) =>
        string.IsNullOrWhiteSpace(routePath) ? "/ingest/windows/base" : "/" + routePath.Trim().Trim('/');
}
