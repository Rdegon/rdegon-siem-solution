namespace Rdegon.WindowsEventAgent.Setup;

internal sealed class SetupCommand
{
    public string Name { get; private set; } = "help";

    public List<string> ForwardArguments { get; } = [];

    public string? GetOption(string optionName)
    {
        for (var index = 1; index < ForwardArguments.Count; index += 1)
        {
            if (!ForwardArguments[index - 1].Equals(optionName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return ForwardArguments[index];
        }

        return null;
    }

    public static SetupCommand Parse(string[] args)
    {
        var command = new SetupCommand();
        if (args.Length == 0)
        {
            return command;
        }

        command.Name = args[0].Trim().ToLowerInvariant();
        command.ForwardArguments.AddRange(args);
        return command;
    }
}
