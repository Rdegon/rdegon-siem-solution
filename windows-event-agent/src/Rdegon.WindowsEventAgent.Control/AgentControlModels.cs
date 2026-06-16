namespace Rdegon.WindowsEventAgent.Control;

internal sealed class AgentControlProfile
{
    public string? InstallDir { get; set; }

    public string? StateDirectory { get; set; }

    public string? ServiceName { get; set; }

    public string? DisplayName { get; set; }

    public string? InstanceName { get; set; }

    public string? BaseUrl { get; set; }

    public string? SharedSecret { get; set; }

    public bool? AllowInvalidServerCertificate { get; set; }

    public int? PollIntervalSeconds { get; set; }

    public int? BatchSize { get; set; }

    public int? MaxSendBatch { get; set; }

    public int? TimeoutSeconds { get; set; }

    public bool? IncludeXml { get; set; }

    public List<WindowsChannelOptions>? Channels { get; set; }
}

internal sealed class AgentControlSettings
{
    public string BundleRoot { get; set; } = string.Empty;

    public string InstallDirectory { get; set; } = string.Empty;

    public string StateDirectory { get; set; } = string.Empty;

    public string ServiceName { get; set; } = "RdegonWindowsEventAgent";

    public string DisplayName { get; set; } = "Rdegon Windows Event Agent";

    public string InstanceName { get; set; } = "default";

    public string BaseUrl { get; set; } = "https://192.168.1.35";

    public string SharedSecret { get; set; } = string.Empty;

    public bool AllowInvalidServerCertificate { get; set; }

    public int PollIntervalSeconds { get; set; } = 60;

    public int BatchSize { get; set; } = 200;

    public int MaxSendBatch { get; set; } = 50;

    public int TimeoutSeconds { get; set; } = 10;

    public bool IncludeXml { get; set; } = true;

    public List<WindowsChannelOptions> Channels { get; set; } = AgentOptions.CreateDefaultChannels();

    public bool StartAfterInstall { get; set; }

    public bool RemoveInstallDirectory { get; set; }

    public bool RemoveStateDirectory { get; set; }

    public string? ProfilePath { get; set; }

    public string ProductionConfigPath => Path.Combine(InstallDirectory, "appsettings.Production.json");

    public string ServiceExecutablePath => Path.Combine(InstallDirectory, "Rdegon.WindowsEventAgent.exe");

    public string BundleServiceExecutablePath => Path.Combine(BundleRoot, "Rdegon.WindowsEventAgent.exe");

    public string SpoolDirectory => Path.Combine(StateDirectory, "spool");

    public string StatusPath => Path.Combine(StateDirectory, "status.json");

    public static AgentControlSettings CreateDefault(string workingDirectory)
    {
        return new AgentControlSettings
        {
            BundleRoot = DetectBundleRoot(),
            InstallDirectory = ResolvePath(workingDirectory, @"%ProgramFiles%\Rdegon\WindowsEventAgent"),
            StateDirectory = ResolvePath(workingDirectory, @"%ProgramData%\RdegonSIEM\WindowsEventAgent"),
        };
    }

    public AgentControlSettings WithProfile(AgentControlProfile profile, string workingDirectory)
    {
        return new AgentControlSettings
        {
            BundleRoot = BundleRoot,
            InstallDirectory = string.IsNullOrWhiteSpace(profile.InstallDir) ? InstallDirectory : ResolvePath(workingDirectory, profile.InstallDir),
            StateDirectory = string.IsNullOrWhiteSpace(profile.StateDirectory) ? StateDirectory : ResolvePath(workingDirectory, profile.StateDirectory),
            ServiceName = string.IsNullOrWhiteSpace(profile.ServiceName) ? ServiceName : profile.ServiceName.Trim(),
            DisplayName = string.IsNullOrWhiteSpace(profile.DisplayName) ? DisplayName : profile.DisplayName.Trim(),
            InstanceName = string.IsNullOrWhiteSpace(profile.InstanceName) ? InstanceName : profile.InstanceName.Trim(),
            BaseUrl = string.IsNullOrWhiteSpace(profile.BaseUrl) ? BaseUrl : profile.BaseUrl.Trim(),
            SharedSecret = profile.SharedSecret ?? SharedSecret,
            AllowInvalidServerCertificate = profile.AllowInvalidServerCertificate ?? AllowInvalidServerCertificate,
            PollIntervalSeconds = profile.PollIntervalSeconds ?? PollIntervalSeconds,
            BatchSize = profile.BatchSize ?? BatchSize,
            MaxSendBatch = profile.MaxSendBatch ?? MaxSendBatch,
            TimeoutSeconds = profile.TimeoutSeconds ?? TimeoutSeconds,
            IncludeXml = profile.IncludeXml ?? IncludeXml,
            Channels = profile.Channels is null ? [.. Channels] : NormalizeChannels(profile.Channels),
            StartAfterInstall = StartAfterInstall,
            RemoveInstallDirectory = RemoveInstallDirectory,
            RemoveStateDirectory = RemoveStateDirectory,
            ProfilePath = ProfilePath,
        };
    }

    public AgentControlSettings WithCommand(AgentControlCommand command, string workingDirectory)
    {
        return new AgentControlSettings
        {
            BundleRoot = ResolvePath(workingDirectory, command.GetValue("bundle-root") ?? BundleRoot),
            InstallDirectory = ResolvePath(workingDirectory, command.GetValue("install-dir") ?? InstallDirectory),
            StateDirectory = ResolvePath(workingDirectory, command.GetValue("state-directory") ?? StateDirectory),
            ServiceName = command.GetValue("service-name") ?? ServiceName,
            DisplayName = command.GetValue("display-name") ?? DisplayName,
            InstanceName = command.GetValue("instance-name") ?? InstanceName,
            BaseUrl = command.GetValue("base-url") ?? BaseUrl,
            SharedSecret = command.GetValue("shared-secret") ?? SharedSecret,
            AllowInvalidServerCertificate = command.HasFlag("allow-invalid-server-certificate") || AllowInvalidServerCertificate,
            PollIntervalSeconds = PollIntervalSeconds,
            BatchSize = BatchSize,
            MaxSendBatch = MaxSendBatch,
            TimeoutSeconds = TimeoutSeconds,
            IncludeXml = IncludeXml,
            Channels = [.. Channels],
            StartAfterInstall = command.HasFlag("start"),
            RemoveInstallDirectory = command.HasFlag("remove-install-dir"),
            RemoveStateDirectory = command.HasFlag("remove-state-dir"),
            ProfilePath = ProfilePath,
        };
    }

    private static string ResolvePath(string workingDirectory, string rawPath)
    {
        var expanded = Environment.ExpandEnvironmentVariables(rawPath.Trim());
        return Path.IsPathRooted(expanded)
            ? Path.GetFullPath(expanded)
            : Path.GetFullPath(Path.Combine(workingDirectory, expanded));
    }

    private static List<WindowsChannelOptions> NormalizeChannels(IEnumerable<WindowsChannelOptions> channels)
    {
        var normalized = channels
            .Where(channel => !string.IsNullOrWhiteSpace(channel.Name) && !string.IsNullOrWhiteSpace(channel.RoutePath))
            .GroupBy(channel => $"{channel.Name}|{channel.RoutePath}", StringComparer.OrdinalIgnoreCase)
            .Select(group => new WindowsChannelOptions
            {
                Name = group.First().Name.Trim(),
                RoutePath = group.First().RoutePath.Trim(),
                Enabled = group.First().Enabled,
            })
            .ToList();

        return normalized.Count == 0 ? AgentOptions.CreateDefaultChannels() : normalized;
    }

    private static string DetectBundleRoot()
    {
        var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        if (File.Exists(Path.Combine(baseDirectory, "Rdegon.WindowsEventAgent.exe")))
        {
            return baseDirectory;
        }

        var candidate = Path.GetFullPath(Path.Combine(baseDirectory, "..", ".."));
        return File.Exists(Path.Combine(candidate, "Rdegon.WindowsEventAgent.exe"))
            ? candidate
            : baseDirectory;
    }
}

internal sealed class AgentConfigurationEnvelope
{
    public AgentOptions Agent { get; set; } = new();
}

internal sealed class StageConfigResult
{
    public string Command { get; set; } = "stage-config";

    public string InstallDirectory { get; set; } = string.Empty;

    public string ProductionConfigPath { get; set; } = string.Empty;

    public string StateDirectory { get; set; } = string.Empty;

    public string SpoolDirectory { get; set; } = string.Empty;

    public string ServiceExecutablePath { get; set; } = string.Empty;

    public string? ProfilePath { get; set; }

    public string InstanceName { get; set; } = string.Empty;

    public string BaseUrl { get; set; } = string.Empty;

    public bool AllowInvalidServerCertificate { get; set; }

    public bool HasSharedSecret { get; set; }
}

internal sealed class ServiceActionResult
{
    public string Command { get; set; } = string.Empty;

    public string ServiceName { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string ExecutablePath { get; set; } = string.Empty;

    public string ProductionConfigPath { get; set; } = string.Empty;

    public string StateDirectory { get; set; } = string.Empty;

    public string SpoolDirectory { get; set; } = string.Empty;

    public bool Started { get; set; }

    public string ServiceStatus { get; set; } = string.Empty;

    public List<string> Actions { get; set; } = [];
}

internal sealed class AgentStatusSummary
{
    public string ServiceName { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string ServiceStatus { get; set; } = "NotInstalled";

    public string BundleRoot { get; set; } = string.Empty;

    public string InstallDirectory { get; set; } = string.Empty;

    public string BundleServiceExecutablePath { get; set; } = string.Empty;

    public string ServiceExecutablePath { get; set; } = string.Empty;

    public string ProductionConfigPath { get; set; } = string.Empty;

    public string StateDirectory { get; set; } = string.Empty;

    public string SpoolDirectory { get; set; } = string.Empty;

    public string StatusPath { get; set; } = string.Empty;

    public int PendingSpoolFiles { get; set; }

    public string InstanceName { get; set; } = string.Empty;

    public string BaseUrl { get; set; } = string.Empty;

    public bool AllowInvalidServerCertificate { get; set; }

    public bool HasSharedSecret { get; set; }

    public bool IsElevated { get; set; }

    public bool EventLogSourceRegistered { get; set; }

    public string? ProfilePath { get; set; }

    public List<WindowsChannelOptions> ConfiguredChannels { get; set; } = [];

    public AgentProcessRuntimeStatus? LiveProcess { get; set; }

    public AgentRuntimeStatus? RuntimeStatus { get; set; }
}

internal sealed class AgentDoctorReport
{
    public string ServiceName { get; set; } = string.Empty;

    public string InstallDirectory { get; set; } = string.Empty;

    public string StateDirectory { get; set; } = string.Empty;

    public string SpoolDirectory { get; set; } = string.Empty;

    public string StatusPath { get; set; } = string.Empty;

    public string ProductionConfigPath { get; set; } = string.Empty;

    public string OverallStatus { get; set; } = "pass";

    public List<DoctorCheck> Checks { get; set; } = [];
}

internal sealed class DoctorCheck
{
    public string Name { get; set; } = string.Empty;

    public string Status { get; set; } = "pass";

    public string Message { get; set; } = string.Empty;

    public static DoctorCheck Pass(string name, string message) => new() { Name = name, Status = "pass", Message = message };

    public static DoctorCheck Warn(string name, string message) => new() { Name = name, Status = "warn", Message = message };

    public static DoctorCheck Fail(string name, string message) => new() { Name = name, Status = "fail", Message = message };
}
