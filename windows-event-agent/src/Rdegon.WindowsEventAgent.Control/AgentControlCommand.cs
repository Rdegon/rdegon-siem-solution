namespace Rdegon.WindowsEventAgent.Control;

internal sealed class AgentControlCommand
{
    public string Name { get; private set; } = "help";

    public string? ProfilePath { get; private set; }

    public Dictionary<string, string> Values { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> Flags { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool ShowHelp => Name is "help" or "--help" or "-h";

    public string? GetValue(string key)
    {
        return Values.TryGetValue(key, out var value) ? value : null;
    }

    public bool HasFlag(string key) => Flags.Contains(key);

    public static AgentControlCommand Parse(string[] args)
    {
        var command = new AgentControlCommand();
        if (args.Length == 0)
        {
            return command;
        }

        command.Name = NormalizeToken(args[0]);
        for (var index = 1; index < args.Length; index += 1)
        {
            var token = args[index]?.Trim() ?? string.Empty;
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Unexpected argument '{token}'. Options must start with --.");
            }

            var key = NormalizeToken(token);
            if (index + 1 < args.Length && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                command.Values[key] = args[index + 1].Trim();
                if (key == "profile")
                {
                    command.ProfilePath = args[index + 1].Trim();
                }

                index += 1;
                continue;
            }

            command.Flags.Add(key);
        }

        return command;
    }

    private static string NormalizeToken(string token) => token.Trim().TrimStart('-').ToLowerInvariant();
}
