using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Rdegon.WindowsEventAgent.Control;

internal static class AgentControlApp
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static async Task<int> RunAsync(string[] args, string workingDirectory, CancellationToken cancellationToken)
    {
        var command = AgentControlCommand.Parse(args);
        if (command.ShowHelp)
        {
            PrintHelp();
            return 0;
        }

        var settings = await BuildSettingsAsync(command, workingDirectory, cancellationToken);
        return command.Name switch
        {
            "status" => await RunStatusAsync(settings, cancellationToken),
            "doctor" => await RunDoctorAsync(settings, cancellationToken),
            "stage-config" => await RunStageConfigAsync(settings, cancellationToken),
            "install-service" => await RunInstallServiceAsync(settings, cancellationToken),
            "uninstall-service" => await RunUninstallServiceAsync(settings, cancellationToken),
            "start" => await RunServiceActionAsync(settings, "start", cancellationToken),
            "stop" => await RunServiceActionAsync(settings, "stop", cancellationToken),
            "restart" => await RunServiceActionAsync(settings, "restart", cancellationToken),
            _ => throw new InvalidOperationException($"Unsupported command '{command.Name}'."),
        };
    }

    private static async Task<AgentControlSettings> BuildSettingsAsync(
        AgentControlCommand command,
        string workingDirectory,
        CancellationToken cancellationToken)
    {
        var settings = AgentControlSettings.CreateDefault(workingDirectory);
        if (!string.IsNullOrWhiteSpace(command.ProfilePath))
        {
            var profilePath = ResolvePath(workingDirectory, command.ProfilePath);
            settings.ProfilePath = profilePath;
            if (!File.Exists(profilePath))
            {
                throw new FileNotFoundException($"Profile file not found: {profilePath}");
            }

            await using var profileStream = File.OpenRead(profilePath);
            var profile = await JsonSerializer.DeserializeAsync<AgentControlProfile>(profileStream, SerializerOptions, cancellationToken)
                          ?? new AgentControlProfile();
            settings = settings.WithProfile(profile, workingDirectory);
            settings.ProfilePath = profilePath;
        }

        settings = settings.WithCommand(command, workingDirectory);
        settings.ProfilePath ??= command.ProfilePath;
        return settings;
    }

    private static async Task<int> RunStatusAsync(AgentControlSettings settings, CancellationToken cancellationToken)
    {
        var payload = await BuildStatusSummaryAsync(settings, cancellationToken);
        PrintJson(payload);
        return 0;
    }

    private static async Task<int> RunDoctorAsync(AgentControlSettings settings, CancellationToken cancellationToken)
    {
        var report = await BuildDoctorReportAsync(settings, cancellationToken);
        PrintJson(report);
        return report.OverallStatus.Equals("fail", StringComparison.OrdinalIgnoreCase) ? 2 : 0;
    }

    private static async Task<int> RunStageConfigAsync(AgentControlSettings settings, CancellationToken cancellationToken)
    {
        var result = await StageConfigurationAsync(settings, cancellationToken);
        PrintJson(result);
        return 0;
    }

    private static async Task<int> RunInstallServiceAsync(AgentControlSettings settings, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureElevated();
        var actions = new List<string>();

        actions.AddRange(await CopyBundleToInstallDirectoryAsync(settings, cancellationToken));
        var stageResult = await StageConfigurationAsync(settings, cancellationToken);
        actions.Add("stage-config");

        if (!File.Exists(settings.ServiceExecutablePath))
        {
            throw new FileNotFoundException($"Agent executable not found: {settings.ServiceExecutablePath}");
        }

        if (!EventLogSourceExists("Rdegon.WindowsEventAgent"))
        {
            try
            {
                EventLog.CreateEventSource("Rdegon.WindowsEventAgent", "Application");
                actions.Add("register-eventlog-source");
            }
            catch (Exception ex)
            {
                actions.Add($"eventlog-source-warning:{ex.Message}");
            }
        }

        if (TryGetServiceController(settings.ServiceName) is { } existingService)
        {
            using (existingService)
            {
                if (existingService.Status != ServiceControllerStatus.Stopped)
                {
                    existingService.Stop();
                    existingService.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                    actions.Add("stop-existing-service");
                }
            }

            await RunScAsync(["delete", settings.ServiceName], cancellationToken);
            actions.Add("delete-existing-service");
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
        }

        await RunScAsync(
            [
                "create",
                settings.ServiceName,
                "binPath=",
                QuotePathForSc(settings.ServiceExecutablePath),
                "start=",
                "auto",
                "DisplayName=",
                settings.DisplayName
            ],
            cancellationToken);
        actions.Add("create-service");

        await RunScAsync(["description", settings.ServiceName, "Native Windows Event Log collector for Rdegon SIEM."], cancellationToken);
        actions.Add("set-description");

        await RunScAsync(["config", settings.ServiceName, "start=", "delayed-auto"], cancellationToken);
        actions.Add("enable-delayed-auto-start");

        await RunScAsync(
            ["failure", settings.ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000"],
            cancellationToken);
        actions.Add("configure-failure-actions");

        if (settings.StartAfterInstall)
        {
            using var controller = new ServiceController(settings.ServiceName);
            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
            actions.Add("start-service");
        }

        PrintJson(new ServiceActionResult
        {
            Command = "install-service",
            ServiceName = settings.ServiceName,
            DisplayName = settings.DisplayName,
            ExecutablePath = settings.ServiceExecutablePath,
            ProductionConfigPath = stageResult.ProductionConfigPath,
            StateDirectory = stageResult.StateDirectory,
            SpoolDirectory = stageResult.SpoolDirectory,
            Started = settings.StartAfterInstall,
            Actions = actions,
        });

        return 0;
    }

    private static async Task<int> RunUninstallServiceAsync(AgentControlSettings settings, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureElevated();

        var actions = new List<string>();
        if (TryGetServiceController(settings.ServiceName) is { } existingService)
        {
            using (existingService)
            {
                if (existingService.Status != ServiceControllerStatus.Stopped)
                {
                    existingService.Stop();
                    existingService.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                    actions.Add("stop-service");
                }
            }

            await RunScAsync(["delete", settings.ServiceName], cancellationToken);
            actions.Add("delete-service");
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
        }
        else
        {
            actions.Add("service-not-installed");
        }

        if (settings.RemoveInstallDirectory && Directory.Exists(settings.InstallDirectory))
        {
            Directory.Delete(settings.InstallDirectory, recursive: true);
            actions.Add("remove-install-directory");
        }

        if (settings.RemoveStateDirectory && Directory.Exists(settings.StateDirectory))
        {
            Directory.Delete(settings.StateDirectory, recursive: true);
            actions.Add("remove-state-directory");
        }

        PrintJson(new ServiceActionResult
        {
            Command = "uninstall-service",
            ServiceName = settings.ServiceName,
            DisplayName = settings.DisplayName,
            ExecutablePath = settings.ServiceExecutablePath,
            ProductionConfigPath = settings.ProductionConfigPath,
            StateDirectory = settings.StateDirectory,
            SpoolDirectory = settings.SpoolDirectory,
            Actions = actions,
        });

        return 0;
    }

    private static Task<int> RunServiceActionAsync(
        AgentControlSettings settings,
        string commandName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var controller = TryGetServiceController(settings.ServiceName)
                              ?? throw new InvalidOperationException($"Service '{settings.ServiceName}' is not installed.");

        var actions = new List<string>();
        switch (commandName)
        {
            case "start":
                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
                actions.Add("start-service");
                break;
            case "stop":
                if (controller.Status != ServiceControllerStatus.Stopped)
                {
                    controller.Stop();
                    controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                    actions.Add("stop-service");
                }
                else
                {
                    actions.Add("already-stopped");
                }
                break;
            case "restart":
                if (controller.Status != ServiceControllerStatus.Stopped)
                {
                    controller.Stop();
                    controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                    actions.Add("stop-service");
                }

                controller.Start();
                controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
                actions.Add("start-service");
                break;
            default:
                throw new InvalidOperationException($"Unsupported service action '{commandName}'.");
        }

        controller.Refresh();
        PrintJson(new ServiceActionResult
        {
            Command = commandName,
            ServiceName = settings.ServiceName,
            DisplayName = settings.DisplayName,
            ExecutablePath = settings.ServiceExecutablePath,
            ProductionConfigPath = settings.ProductionConfigPath,
            StateDirectory = settings.StateDirectory,
            SpoolDirectory = settings.SpoolDirectory,
            Actions = actions,
            ServiceStatus = controller.Status.ToString(),
        });

        return Task.FromResult(0);
    }

    private static async Task<StageConfigResult> StageConfigurationAsync(
        AgentControlSettings settings,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        Directory.CreateDirectory(settings.InstallDirectory);
        Directory.CreateDirectory(settings.StateDirectory);
        Directory.CreateDirectory(settings.SpoolDirectory);

        var envelope = new AgentConfigurationEnvelope
        {
            Agent = new AgentOptions
            {
                InstanceName = settings.InstanceName,
                BaseUrl = settings.BaseUrl,
                PollIntervalSeconds = settings.PollIntervalSeconds,
                BatchSize = settings.BatchSize,
                MaxSendBatch = settings.MaxSendBatch,
                TimeoutSeconds = settings.TimeoutSeconds,
                IncludeXml = settings.IncludeXml,
                SharedSecret = settings.SharedSecret,
                AllowInvalidServerCertificate = settings.AllowInvalidServerCertificate,
                StateDirectory = settings.StateDirectory,
                SpoolDirectory = settings.SpoolDirectory,
                Channels = NormalizeChannels(settings.Channels).ToList(),
            }
        };

        await using var stream = File.Create(settings.ProductionConfigPath);
        await JsonSerializer.SerializeAsync(stream, envelope, SerializerOptions, cancellationToken);

        return new StageConfigResult
        {
            Command = "stage-config",
            InstallDirectory = settings.InstallDirectory,
            ProductionConfigPath = settings.ProductionConfigPath,
            StateDirectory = settings.StateDirectory,
            SpoolDirectory = settings.SpoolDirectory,
            ServiceExecutablePath = settings.ServiceExecutablePath,
            ProfilePath = settings.ProfilePath,
            InstanceName = settings.InstanceName,
            BaseUrl = settings.BaseUrl,
            AllowInvalidServerCertificate = settings.AllowInvalidServerCertificate,
            HasSharedSecret = !string.IsNullOrWhiteSpace(settings.SharedSecret),
        };
    }

    private static async Task<AgentStatusSummary> BuildStatusSummaryAsync(
        AgentControlSettings settings,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var summary = new AgentStatusSummary
        {
            ServiceName = settings.ServiceName,
            DisplayName = settings.DisplayName,
            ServiceStatus = GetServiceStatus(settings.ServiceName),
            BundleRoot = settings.BundleRoot,
            InstallDirectory = settings.InstallDirectory,
            ServiceExecutablePath = settings.ServiceExecutablePath,
            BundleServiceExecutablePath = settings.BundleServiceExecutablePath,
            ProductionConfigPath = settings.ProductionConfigPath,
            StateDirectory = settings.StateDirectory,
            SpoolDirectory = settings.SpoolDirectory,
            StatusPath = settings.StatusPath,
            PendingSpoolFiles = Directory.Exists(settings.SpoolDirectory)
                ? Directory.EnumerateFiles(settings.SpoolDirectory, "*.json").Count()
                : 0,
            IsElevated = IsElevated(),
            EventLogSourceRegistered = EventLogSourceExists("Rdegon.WindowsEventAgent"),
            ProfilePath = settings.ProfilePath,
            InstanceName = settings.InstanceName,
            BaseUrl = settings.BaseUrl,
            AllowInvalidServerCertificate = settings.AllowInvalidServerCertificate,
            HasSharedSecret = !string.IsNullOrWhiteSpace(settings.SharedSecret),
            ConfiguredChannels = NormalizeChannels(settings.Channels).ToList(),
        };

        if (File.Exists(settings.ProductionConfigPath))
        {
            var config = await LoadConfigurationEnvelopeAsync(settings.ProductionConfigPath, cancellationToken);
            if (config?.Agent is { } agent)
            {
                summary.InstanceName = agent.InstanceName;
                summary.BaseUrl = agent.BaseUrl;
                summary.AllowInvalidServerCertificate = agent.AllowInvalidServerCertificate;
                summary.HasSharedSecret = !string.IsNullOrWhiteSpace(agent.SharedSecret);
                summary.ConfiguredChannels = NormalizeChannels(agent.Channels).ToList();
            }
        }

        if (File.Exists(settings.StatusPath))
        {
            await using var statusStream = File.OpenRead(settings.StatusPath);
            summary.RuntimeStatus = await JsonSerializer.DeserializeAsync<AgentRuntimeStatus>(statusStream, SerializerOptions, cancellationToken);
        }

        var liveProcessId = TryGetServiceProcessId(settings.ServiceName)
                            ?? summary.RuntimeStatus?.Process?.ProcessId;
        summary.LiveProcess = AgentProcessStatusSampler.TryCaptureByProcessId(liveProcessId ?? 0)
                              ?? summary.RuntimeStatus?.Process;

        return summary;
    }

    private static async Task<AgentDoctorReport> BuildDoctorReportAsync(
        AgentControlSettings settings,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var checks = new List<DoctorCheck>();
        var statusSummary = await BuildStatusSummaryAsync(settings, cancellationToken);
        AgentConfigurationEnvelope? envelope = null;

        checks.Add(Directory.Exists(settings.InstallDirectory)
            ? DoctorCheck.Pass("install-dir", $"Install directory exists: {settings.InstallDirectory}")
            : DoctorCheck.Warn("install-dir", $"Install directory does not exist yet: {settings.InstallDirectory}"));

        checks.Add(Directory.Exists(settings.BundleRoot)
            ? DoctorCheck.Pass("bundle-root", $"Bundle root exists: {settings.BundleRoot}")
            : DoctorCheck.Fail("bundle-root", $"Bundle root does not exist: {settings.BundleRoot}"));

        checks.Add(File.Exists(settings.BundleServiceExecutablePath)
            ? DoctorCheck.Pass("bundle-service-exe", $"Bundle contains agent executable: {settings.BundleServiceExecutablePath}")
            : DoctorCheck.Warn("bundle-service-exe", $"Bundle service executable is not present at: {settings.BundleServiceExecutablePath}"));

        checks.Add(File.Exists(settings.ServiceExecutablePath)
            ? DoctorCheck.Pass("service-exe", $"Agent executable found: {settings.ServiceExecutablePath}")
            : DoctorCheck.Fail("service-exe", $"Agent executable is missing: {settings.ServiceExecutablePath}"));

        if (File.Exists(settings.ProductionConfigPath))
        {
            try
            {
                envelope = await LoadConfigurationEnvelopeAsync(settings.ProductionConfigPath, cancellationToken);
                checks.Add(envelope?.Agent is null
                    ? DoctorCheck.Fail("production-config", $"Production config is missing the Agent section: {settings.ProductionConfigPath}")
                    : DoctorCheck.Pass("production-config", $"Production config parsed successfully: {settings.ProductionConfigPath}"));
            }
            catch (Exception ex)
            {
                checks.Add(DoctorCheck.Fail("production-config", $"Unable to parse production config: {ex.Message}"));
            }
        }
        else
        {
            checks.Add(DoctorCheck.Warn("production-config", $"Production config has not been staged yet: {settings.ProductionConfigPath}"));
        }

        checks.Add(TestDirectoryWritable(settings.StateDirectory, "state-dir"));
        checks.Add(TestDirectoryWritable(settings.SpoolDirectory, "spool-dir"));

        checks.Add(statusSummary.ServiceStatus == "NotInstalled"
            ? DoctorCheck.Warn("service-status", $"Service '{settings.ServiceName}' is not installed.")
            : DoctorCheck.Pass("service-status", $"Service status: {statusSummary.ServiceStatus}"));

        if (statusSummary.LiveProcess is { } liveProcess)
        {
            var workingSetMb = Math.Round(liveProcess.WorkingSetBytes / 1_048_576d, 2);
            var privateMb = Math.Round(liveProcess.PrivateMemoryBytes / 1_048_576d, 2);
            var message =
                $"PID {liveProcess.ProcessId}; working set {workingSetMb} MB; private {privateMb} MB; threads {liveProcess.ThreadCount}; handles {liveProcess.HandleCount}.";

            checks.Add(workingSetMb > 300 || privateMb > 500
                ? DoctorCheck.Warn("process-memory", message)
                : DoctorCheck.Pass("process-memory", message));
        }
        else
        {
            checks.Add(DoctorCheck.Warn("process-memory", "Live process metrics are not available yet. Start the service and rerun doctor."));
        }

        checks.Add(IsElevated()
            ? DoctorCheck.Pass("elevation", "Current session is elevated and can register the Windows service.")
            : DoctorCheck.Warn("elevation", "Current session is not elevated. Service installation will require Administrator privileges."));

        checks.Add(EventLogSourceExists("Rdegon.WindowsEventAgent")
            ? DoctorCheck.Pass("eventlog-source", "Windows Event Log source is registered.")
            : DoctorCheck.Warn("eventlog-source", "Windows Event Log source is not registered yet."));

        if (File.Exists(settings.StatusPath))
        {
            try
            {
                await using var statusStream = File.OpenRead(settings.StatusPath);
                var runtimeStatus = await JsonSerializer.DeserializeAsync<AgentRuntimeStatus>(statusStream, SerializerOptions, cancellationToken);
                checks.Add(runtimeStatus is null
                    ? DoctorCheck.Warn("runtime-status", $"Runtime status file is present but empty: {settings.StatusPath}")
                    : DoctorCheck.Pass("runtime-status", $"Runtime status file parsed successfully: {settings.StatusPath}"));
            }
            catch (Exception ex)
            {
                checks.Add(DoctorCheck.Fail("runtime-status", $"Unable to parse runtime status file: {ex.Message}"));
            }
        }
        else
        {
            checks.Add(DoctorCheck.Warn("runtime-status", $"Runtime status file is not present yet: {settings.StatusPath}"));
        }

        var configuredAgent = envelope?.Agent ?? new AgentOptions
        {
            InstanceName = settings.InstanceName,
            BaseUrl = settings.BaseUrl,
            PollIntervalSeconds = settings.PollIntervalSeconds,
            BatchSize = settings.BatchSize,
            MaxSendBatch = settings.MaxSendBatch,
            TimeoutSeconds = settings.TimeoutSeconds,
            IncludeXml = settings.IncludeXml,
            StateDirectory = settings.StateDirectory,
            SpoolDirectory = settings.SpoolDirectory,
            AllowInvalidServerCertificate = settings.AllowInvalidServerCertificate,
            SharedSecret = settings.SharedSecret,
            Channels = NormalizeChannels(settings.Channels).ToList(),
        };

        checks.Add(Uri.TryCreate(configuredAgent.BaseUrl, UriKind.Absolute, out var baseUri)
            ? baseUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
                ? DoctorCheck.Pass("base-url", $"Base URL is valid HTTPS: {configuredAgent.BaseUrl}")
                : DoctorCheck.Warn("base-url", $"Base URL is valid but not HTTPS: {configuredAgent.BaseUrl}")
            : DoctorCheck.Fail("base-url", $"Base URL is not a valid absolute URI: {configuredAgent.BaseUrl}"));

        checks.Add(configuredAgent.AllowInvalidServerCertificate
            ? DoctorCheck.Warn("tls-validation", "Invalid server certificates are allowed. Use this only in lab environments.")
            : DoctorCheck.Pass("tls-validation", "Server certificate validation is enforced."));

        try
        {
            var availableLogs = EventLogSession.GlobalSession
                .GetLogNames()
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var enabledChannels = NormalizeChannels(configuredAgent.Channels)
                .Where(channel => channel.Enabled)
                .ToList();

            if (enabledChannels.Count == 0)
            {
                checks.Add(DoctorCheck.Fail("channels", "No enabled Windows channels are configured."));
            }

            foreach (var channel in enabledChannels)
            {
                checks.Add(availableLogs.Contains(channel.Name)
                    ? DoctorCheck.Pass($"channel:{channel.Name}", $"Windows channel is available: {channel.Name}")
                    : DoctorCheck.Fail($"channel:{channel.Name}", $"Windows channel is missing on this host: {channel.Name}"));
            }
        }
        catch (Exception ex)
        {
            checks.Add(DoctorCheck.Warn("channel-query", $"Unable to query Windows Event Log channels from this session: {ex.Message}"));
        }

        var overallStatus = checks.Any(check => check.Status == "fail")
            ? "fail"
            : checks.Any(check => check.Status == "warn")
                ? "warn"
                : "pass";

        return new AgentDoctorReport
        {
            ServiceName = settings.ServiceName,
            InstallDirectory = settings.InstallDirectory,
            StateDirectory = settings.StateDirectory,
            SpoolDirectory = settings.SpoolDirectory,
            StatusPath = settings.StatusPath,
            ProductionConfigPath = settings.ProductionConfigPath,
            OverallStatus = overallStatus,
            Checks = checks,
        };
    }

    private static IEnumerable<WindowsChannelOptions> NormalizeChannels(IEnumerable<WindowsChannelOptions> channels)
    {
        var normalized = channels
            .Where(channel => !string.IsNullOrWhiteSpace(channel.Name) && !string.IsNullOrWhiteSpace(channel.RoutePath))
            .GroupBy(channel => $"{channel.Name}|{channel.RoutePath}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();

        return normalized.Count == 0 ? AgentOptions.CreateDefaultChannels() : normalized;
    }

    private static DoctorCheck TestDirectoryWritable(string path, string checkName)
    {
        try
        {
            Directory.CreateDirectory(path);
            var probePath = Path.Combine(path, $".rdegon-probe-{Guid.NewGuid():N}.tmp");
            File.WriteAllText(probePath, DateTimeOffset.UtcNow.ToString("O"));
            File.Delete(probePath);
            return DoctorCheck.Pass(checkName, $"Directory is writable: {path}");
        }
        catch (Exception ex)
        {
            return DoctorCheck.Fail(checkName, $"Directory is not writable: {path}. {ex.Message}");
        }
    }

    private static ServiceController? TryGetServiceController(string serviceName)
    {
        try
        {
            var controller = new ServiceController(serviceName);
            _ = controller.Status;
            return controller;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static string GetServiceStatus(string serviceName)
    {
        using var controller = TryGetServiceController(serviceName);
        return controller?.Status.ToString() ?? "NotInstalled";
    }

    private static int? TryGetServiceProcessId(string serviceName)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            }
        };

        process.StartInfo.ArgumentList.Add("queryex");
        process.StartInfo.ArgumentList.Add(serviceName);
        process.Start();
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(stderr))
        {
            return null;
        }

        var match = Regex.Match(stdout, @"PID\s*:\s*(\d+)", RegexOptions.IgnoreCase);
        return match.Success && int.TryParse(match.Groups[1].Value, out var pid) && pid > 0
            ? pid
            : null;
    }

    private static async Task<AgentConfigurationEnvelope?> LoadConfigurationEnvelopeAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var configStream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync<AgentConfigurationEnvelope>(configStream, SerializerOptions, cancellationToken);
    }

    private static void PrintJson<T>(T payload)
    {
        Console.WriteLine(JsonSerializer.Serialize(payload, SerializerOptions));
    }

    private static bool IsElevated()
    {
        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static void EnsureElevated()
    {
        if (!IsElevated())
        {
            throw new InvalidOperationException("Administrator privileges are required for this command.");
        }
    }

    private static bool EventLogSourceExists(string sourceName)
    {
        using var sourceKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\EventLog\Application\{sourceName}");
        return sourceKey is not null;
    }

    private static async Task RunScAsync(IEnumerable<string> arguments, CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            }
        };

        foreach (var argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (process.ExitCode != 0)
        {
            var message = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            throw new InvalidOperationException($"sc.exe failed with exit code {process.ExitCode}: {message.Trim()}");
        }
    }

    private static string ResolvePath(string workingDirectory, string rawPath)
    {
        var expanded = Environment.ExpandEnvironmentVariables(rawPath.Trim());
        return Path.IsPathRooted(expanded)
            ? Path.GetFullPath(expanded)
            : Path.GetFullPath(Path.Combine(workingDirectory, expanded));
    }

    private static string QuotePathForSc(string path) => $"\"{path}\"";

    private static async Task<IReadOnlyList<string>> CopyBundleToInstallDirectoryAsync(
        AgentControlSettings settings,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var sourceRoot = Path.GetFullPath(settings.BundleRoot);
        var destinationRoot = Path.GetFullPath(settings.InstallDirectory);
        if (PathsEqual(sourceRoot, destinationRoot))
        {
            return ["bundle-already-installed"];
        }

        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException($"Bundle root does not exist: {sourceRoot}");
        }

        if (IsSubPathOf(destinationRoot, sourceRoot))
        {
            throw new InvalidOperationException("Install directory cannot be inside the bundle root. Pick a separate destination path.");
        }

        if (!File.Exists(Path.Combine(sourceRoot, "Rdegon.WindowsEventAgent.exe")))
        {
            throw new FileNotFoundException($"Bundle root does not contain Rdegon.WindowsEventAgent.exe: {sourceRoot}");
        }

        Directory.CreateDirectory(destinationRoot);
        await CopyDirectoryRecursiveAsync(sourceRoot, destinationRoot, cancellationToken);
        return [$"copy-bundle:{sourceRoot}->{destinationRoot}"];
    }

    private static async Task CopyDirectoryRecursiveAsync(string sourceRoot, string destinationRoot, CancellationToken cancellationToken)
    {
        foreach (var directory in Directory.EnumerateDirectories(sourceRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Path.GetRelativePath(sourceRoot, directory);
            Directory.CreateDirectory(Path.Combine(destinationRoot, relativePath));
        }

        foreach (var file in Directory.EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relativePath = Path.GetRelativePath(sourceRoot, file);
            var destinationPath = Path.Combine(destinationRoot, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            File.Copy(file, destinationPath, overwrite: true);
            await Task.Yield();
        }
    }

    private static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.GetFullPath(left).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetFullPath(right).TrimEnd(Path.DirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

    private static bool IsSubPathOf(string candidatePath, string rootPath)
    {
        var candidate = Path.GetFullPath(candidatePath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var root = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase) && !PathsEqual(candidatePath, rootPath);
    }

    private static void PrintHelp()
    {
        Console.WriteLine(
            """
            Rdegon.WindowsEventAgent.Control

            Commands:
              status
              doctor
              stage-config
              install-service
              uninstall-service
              start
              stop
              restart

            Common options:
              --profile <path>
              --bundle-root <path>
              --install-dir <path>
              --state-directory <path>
              --service-name <name>
              --display-name <name>
              --instance-name <name>
              --base-url <https://ingest-host>
              --shared-secret <secret>
              --allow-invalid-server-certificate
              --start
              --remove-install-dir
              --remove-state-dir

            Example:
              Rdegon.WindowsEventAgent.Control.exe doctor --profile C:\ops\windows-agent-profile.local.json
            """);
    }
}
