namespace Rdegon.WindowsEventAgent;

public sealed class AgentRuntimeMode
{
    public bool RunOnce { get; init; }

    public bool PrintConfig { get; init; }

    public bool PrintStatusPath { get; init; }

    public bool RunAsWindowsService => !(RunOnce || PrintConfig || PrintStatusPath);

    public static AgentRuntimeMode Parse(string[] args)
    {
        var normalized = args
            .Select(arg => (arg ?? string.Empty).Trim().ToLowerInvariant())
            .Where(arg => !string.IsNullOrWhiteSpace(arg))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return new AgentRuntimeMode
        {
            RunOnce = normalized.Contains("--run-once"),
            PrintConfig = normalized.Contains("--print-config"),
            PrintStatusPath = normalized.Contains("--print-status-path"),
        };
    }
}
