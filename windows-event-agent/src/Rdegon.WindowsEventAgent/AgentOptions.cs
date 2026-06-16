using System.ComponentModel.DataAnnotations;

namespace Rdegon.WindowsEventAgent;

public sealed class AgentOptions
{
    [Required]
    public string InstanceName { get; set; } = "default";

    [Required]
    public string BaseUrl { get; set; } = "https://192.168.1.35";

    [Range(1, 3600)]
    public int PollIntervalSeconds { get; set; } = 60;

    [Range(1, 5000)]
    public int BatchSize { get; set; } = 200;

    [Range(1, 5000)]
    public int MaxSendBatch { get; set; } = 50;

    [Range(1, 300)]
    public int TimeoutSeconds { get; set; } = 10;

    public bool IncludeXml { get; set; } = true;

    public bool AllowInvalidServerCertificate { get; set; } = false;

    public string SharedSecret { get; set; } = string.Empty;

    public string StateDirectory { get; set; } = @"%ProgramData%\RdegonSIEM\WindowsEventAgent";

    public string SpoolDirectory { get; set; } = string.Empty;

    public List<WindowsChannelOptions> Channels { get; set; } = [];

    public static List<WindowsChannelOptions> CreateDefaultChannels() =>
    [
        new WindowsChannelOptions { Name = "Security", RoutePath = "/ingest/windows/security" },
        new WindowsChannelOptions { Name = "System", RoutePath = "/ingest/windows/base" },
        new WindowsChannelOptions { Name = "Application", RoutePath = "/ingest/windows/base" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-Sysmon/Operational", RoutePath = "/ingest/windows/sysmon" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-PowerShell/Operational", RoutePath = "/ingest/windows/powershell" },
        new WindowsChannelOptions { Name = "Windows PowerShell", RoutePath = "/ingest/windows/powershell" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-Windows Defender/Operational", RoutePath = "/ingest/windows/base" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-WMI-Activity/Operational", RoutePath = "/ingest/windows/base" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", RoutePath = "/ingest/windows/base" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", RoutePath = "/ingest/windows/base" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-TaskScheduler/Operational", RoutePath = "/ingest/windows/base" },
        new WindowsChannelOptions { Name = "Microsoft-Windows-WinRM/Operational", RoutePath = "/ingest/windows/base" },
    ];
}

public sealed class WindowsChannelOptions
{
    [Required]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string RoutePath { get; set; } = "/ingest/windows/base";

    public bool Enabled { get; set; } = true;
}
