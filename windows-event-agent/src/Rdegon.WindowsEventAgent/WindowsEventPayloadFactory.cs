using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;
using Microsoft.Extensions.Options;

namespace Rdegon.WindowsEventAgent;

public sealed class WindowsEventPayloadFactory
{
    private readonly AgentOptions _options;

    public WindowsEventPayloadFactory(IOptions<AgentOptions> options)
    {
        _options = options.Value;
    }

    public Task<ChannelReadResult> ReadNewEventsAsync(WindowsChannelOptions channel, long lastRecordId, CancellationToken cancellationToken)
    {
        return Task.Run(() => ReadNewEvents(channel, lastRecordId, cancellationToken), cancellationToken);
    }

    private ChannelReadResult ReadNewEvents(WindowsChannelOptions channel, long lastRecordId, CancellationToken cancellationToken)
    {
        var queryText = lastRecordId > 0
            ? $"*[System[(EventRecordID>{lastRecordId.ToString(CultureInfo.InvariantCulture)})]]"
            : "*";

        var query = new EventLogQuery(channel.Name, PathType.LogName, queryText)
        {
            ReverseDirection = false,
            TolerateQueryErrors = true
        };

        var items = new List<Dictionary<string, object?>>();
        long newestRecordId = lastRecordId;

        using var reader = new EventLogReader(query);

        for (var index = 0; index < Math.Max(1, _options.BatchSize); index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var record = reader.ReadEvent();
            if (record is null)
            {
                break;
            }

            var recordId = record.RecordId ?? 0L;
            if (recordId <= lastRecordId)
            {
                continue;
            }

            var xml = SafeXml(record);
            items.Add(BuildPayload(channel.Name, record, xml));
            newestRecordId = Math.Max(newestRecordId, recordId);
        }

        return new ChannelReadResult(channel.RoutePath, items, newestRecordId);
    }

    private Dictionary<string, object?> BuildPayload(string channelName, EventRecord record, string xml)
    {
        var providerName = SanitizeString(record.ProviderName);
        var machineName = SanitizeString(record.MachineName) is { Length: > 0 } machine ? machine : Environment.MachineName;
        var recordId = record.RecordId ?? 0L;
        var eventId = record.Id;
        var eventData = ParseEventData(xml);

        return new Dictionary<string, object?>
        {
            ["source_type"] = "windows_event_json",
            ["collector"] = "windows_agent",
            ["source"] = Environment.MachineName,
            ["host"] = new Dictionary<string, object?> { ["name"] = Environment.MachineName },
            ["computer_name"] = machineName,
            ["channel"] = channelName,
            ["provider"] = providerName,
            ["event_id"] = eventId,
            ["event_code"] = eventId.ToString(CultureInfo.InvariantCulture),
            ["record_id"] = recordId,
            ["level"] = SafeMetadata(() => record.LevelDisplayName),
            ["task"] = SafeMetadata(() => record.TaskDisplayName),
            ["opcode"] = SafeMetadata(() => record.OpcodeDisplayName),
            ["keywords"] = string.Join(",", SafeKeywordDisplayNames(record)),
            ["time_created"] = record.TimeCreated?.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture) ?? string.Empty,
            ["message"] = SafeDescription(record),
            ["event"] = new Dictionary<string, object?>
            {
                ["provider"] = providerName,
                ["id"] = eventId.ToString(CultureInfo.InvariantCulture),
                ["code"] = eventId.ToString(CultureInfo.InvariantCulture),
                ["type"] = "windows_event"
            },
            ["windows"] = new Dictionary<string, object?>
            {
                ["xml"] = _options.IncludeXml ? xml : null,
                ["event_data"] = eventData
            }
        }.ToDictionary(kvp => kvp.Key, kvp => SanitizeValue(kvp.Value));
    }

    private static string SafeDescription(EventRecord record)
    {
        try
        {
            return SanitizeString(record.FormatDescription());
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string SafeXml(EventRecord record)
    {
        try
        {
            return SanitizeString(record.ToXml());
        }
        catch
        {
            return string.Empty;
        }
    }

    private static Dictionary<string, string> ParseEventData(string xml)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(xml))
        {
            return result;
        }

        try
        {
            var document = XDocument.Parse(xml);
            var root = document.Root;
            if (root is null)
            {
                return result;
            }

            var ns = root.Name.Namespace;
            foreach (var node in root.Descendants(ns + "EventData").Elements(ns + "Data"))
            {
                var name = (string?)node.Attribute("Name");
                if (string.IsNullOrWhiteSpace(name))
                {
                    name = $"field_{result.Count + 1}";
                }

                var value = (node.Value ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    result[name] = SanitizeString(value);
                }
            }

            foreach (var container in root.Descendants(ns + "UserData").Elements())
            {
                foreach (var node in container.Elements())
                {
                    var name = node.Name.LocalName;
                    var value = (node.Value ?? string.Empty).Trim();
                    if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(value) && !result.ContainsKey(name))
                    {
                        result[name] = SanitizeString(value);
                    }
                }
            }
        }
        catch
        {
            return result;
        }

        return result;
    }

    private static string SafeMetadata(Func<string?> accessor)
    {
        try
        {
            return SanitizeString(accessor());
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string[] SafeKeywordDisplayNames(EventRecord record)
    {
        try
        {
            return (record.KeywordsDisplayNames ?? Array.Empty<string>())
                .Select(SanitizeString)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static object? SanitizeValue(object? value)
    {
        return value switch
        {
            null => null,
            string text => SanitizeString(text),
            Dictionary<string, object?> dictionary => dictionary.ToDictionary(kvp => kvp.Key, kvp => SanitizeValue(kvp.Value)),
            Dictionary<string, string> dictionary => dictionary.ToDictionary(kvp => kvp.Key, kvp => SanitizeString(kvp.Value)),
            IEnumerable<string> items => items.Select(SanitizeString).ToArray(),
            _ => value
        };
    }

    private static string SanitizeString(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var builder = new System.Text.StringBuilder(value.Length);
        for (var index = 0; index < value.Length; index++)
        {
            var current = value[index];
            if (char.IsHighSurrogate(current))
            {
                if (index + 1 < value.Length && char.IsLowSurrogate(value[index + 1]))
                {
                    builder.Append(current);
                    builder.Append(value[++index]);
                }

                continue;
            }

            if (char.IsLowSurrogate(current))
            {
                continue;
            }

            if (char.IsControl(current) && current is not '\t' and not '\r' and not '\n')
            {
                continue;
            }

            builder.Append(current);
        }

        return builder.ToString();
    }
}

public sealed class ChannelReadResult(string routePath, List<Dictionary<string, object?>> events, long newestRecordId)
{
    public string RoutePath { get; } = routePath;

    public List<Dictionary<string, object?>> Events { get; } = events;

    public long NewestRecordId { get; } = newestRecordId;
}
