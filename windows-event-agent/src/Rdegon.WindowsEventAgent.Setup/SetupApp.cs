using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;

namespace Rdegon.WindowsEventAgent.Setup;

internal static class SetupApp
{
    private const string BundleZipResourceName = "Rdegon.WindowsEventAgent.Setup.Payload.BundleZip";
    private const string InstallGuideResourceName = "Rdegon.WindowsEventAgent.Setup.Payload.InstallGuide";
    private const string ProfileTemplateResourceName = "Rdegon.WindowsEventAgent.Setup.Payload.ProfileTemplate";

    private static readonly HashSet<string> ControlCommands =
    [
        "status",
        "doctor",
        "stage-config",
        "install-service",
        "uninstall-service",
        "start",
        "stop",
        "restart",
    ];

    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken)
    {
        var command = SetupCommand.Parse(args);
        return command.Name switch
        {
            "help" or "--help" or "-h" => ShowHelp(),
            "show-install-guide" => await ShowInstallGuideAsync(cancellationToken),
            "write-profile-template" => await WriteProfileTemplateAsync(command, cancellationToken),
            "extract-bundle" => await ExtractBundleAsync(command, cancellationToken),
            _ when ControlCommands.Contains(command.Name) => await ForwardToControlToolAsync(command, cancellationToken),
            _ => throw new InvalidOperationException($"Unknown command '{command.Name}'. Run 'help' to see supported commands."),
        };
    }

    private static int ShowHelp()
    {
        Console.WriteLine(
            """
            Rdegon.WindowsEventAgent.Setup

            Commands:
              help
              show-install-guide
              write-profile-template --output <path>
              extract-bundle --output-dir <path>
              doctor [control options]
              status [control options]
              stage-config [control options]
              install-service [control options]
              uninstall-service [control options]
              start [control options]
              stop [control options]
              restart [control options]

            Typical flow:
              Rdegon.WindowsEventAgent.Setup.exe write-profile-template --output C:\Ops\windows-agent-profile.local.json
              Rdegon.WindowsEventAgent.Setup.exe doctor --profile C:\Ops\windows-agent-profile.local.json
              Rdegon.WindowsEventAgent.Setup.exe install-service --profile C:\Ops\windows-agent-profile.local.json --start
            """);

        return 0;
    }

    private static async Task<int> ShowInstallGuideAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Console.WriteLine(await ReadTextResourceAsync(InstallGuideResourceName, cancellationToken));
        return 0;
    }

    private static async Task<int> WriteProfileTemplateAsync(SetupCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var outputPath = command.GetOption("--output")
                         ?? throw new InvalidOperationException("The --output option is required.");

        var resolvedPath = ResolvePath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(resolvedPath)!);
        await File.WriteAllTextAsync(
            resolvedPath,
            await ReadTextResourceAsync(ProfileTemplateResourceName, cancellationToken),
            cancellationToken);

        Console.WriteLine(resolvedPath);
        return 0;
    }

    private static async Task<int> ExtractBundleAsync(SetupCommand command, CancellationToken cancellationToken)
    {
        var outputDirectory = command.GetOption("--output-dir")
                              ?? throw new InvalidOperationException("The --output-dir option is required.");

        var resolvedDirectory = ResolvePath(outputDirectory);
        await ExtractBundleToDirectoryAsync(resolvedDirectory, overwrite: true, cancellationToken);
        Console.WriteLine(resolvedDirectory);
        return 0;
    }

    private static async Task<int> ForwardToControlToolAsync(SetupCommand command, CancellationToken cancellationToken)
    {
        var callerWorkingDirectory = Directory.GetCurrentDirectory();
        var tempRoot = Path.Combine(Path.GetTempPath(), "RdegonWindowsEventAgentSetup", Guid.NewGuid().ToString("N"));
        try
        {
            await ExtractBundleToDirectoryAsync(tempRoot, overwrite: true, cancellationToken);
            var controlExePath = Path.Combine(tempRoot, "tools", "control", "Rdegon.WindowsEventAgent.Control.exe");
            if (!File.Exists(controlExePath))
            {
                throw new FileNotFoundException($"Extracted control tool is missing: {controlExePath}");
            }

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = controlExePath,
                    // Keep relative user-supplied paths anchored to the directory where setup.exe was launched.
                    WorkingDirectory = callerWorkingDirectory,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                }
            };

            foreach (var argument in command.ForwardArguments)
            {
                process.StartInfo.ArgumentList.Add(argument);
            }

            process.Start();
            var stdoutTask = PipeStreamAsync(process.StandardOutput, Console.Out, cancellationToken);
            var stderrTask = PipeStreamAsync(process.StandardError, Console.Error, cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(stdoutTask, stderrTask);
            return process.ExitCode;
        }
        finally
        {
            TryDeleteDirectory(tempRoot);
        }
    }

    private static async Task ExtractBundleToDirectoryAsync(string outputDirectory, bool overwrite, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (overwrite && Directory.Exists(outputDirectory))
        {
            Directory.Delete(outputDirectory, recursive: true);
        }

        Directory.CreateDirectory(outputDirectory);
        var zipPath = Path.Combine(outputDirectory, "bundle.zip");
        await using (var resourceStream = OpenRequiredResource(BundleZipResourceName))
        await using (var fileStream = File.Create(zipPath))
        {
            await resourceStream.CopyToAsync(fileStream, cancellationToken);
        }

        ZipFile.ExtractToDirectory(zipPath, outputDirectory, overwriteFiles: true);
        File.Delete(zipPath);
    }

    private static async Task<string> ReadTextResourceAsync(string resourceName, CancellationToken cancellationToken)
    {
        await using var stream = OpenRequiredResource(resourceName);
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(cancellationToken);
    }

    private static Stream OpenRequiredResource(string resourceName)
    {
        return Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
               ?? throw new InvalidOperationException($"Embedded resource '{resourceName}' is missing.");
    }

    private static async Task PipeStreamAsync(StreamReader source, TextWriter destination, CancellationToken cancellationToken)
    {
        while (!source.EndOfStream)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = await source.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                break;
            }

            await destination.WriteLineAsync(line);
        }
    }

    private static string ResolvePath(string rawPath)
    {
        var expanded = Environment.ExpandEnvironmentVariables(rawPath.Trim());
        return Path.IsPathRooted(expanded)
            ? Path.GetFullPath(expanded)
            : Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), expanded));
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
        }
    }
}
