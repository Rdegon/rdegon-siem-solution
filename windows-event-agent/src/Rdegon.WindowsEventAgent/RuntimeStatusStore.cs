using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Rdegon.WindowsEventAgent;

public sealed class RuntimeStatusStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly string _statusPath;

    public RuntimeStatusStore(IOptions<AgentOptions> options)
    {
        var stateDirectory = BookmarkStore.ResolveStateDirectory(options.Value);
        Directory.CreateDirectory(stateDirectory);
        _statusPath = Path.Combine(stateDirectory, "status.json");
    }

    public string StatusPath => _statusPath;

    public async Task WriteAsync(AgentRuntimeStatus status, CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await using var stream = File.Create(_statusPath);
            await JsonSerializer.SerializeAsync(stream, status, SerializerOptions, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }
}

public sealed class AgentRuntimeStatus
{
    public string InstanceName { get; set; } = "default";

    public string MachineName { get; set; } = Environment.MachineName;

    public string Status { get; set; } = "starting";

    public string StartedUtc { get; set; } = string.Empty;

    public string LastCycleStartedUtc { get; set; } = string.Empty;

    public string LastCycleCompletedUtc { get; set; } = string.Empty;

    public string LastSuccessfulDeliveryUtc { get; set; } = string.Empty;

    public string LastError { get; set; } = string.Empty;

    public string StatusPath { get; set; } = string.Empty;

    public int PendingSpoolFiles { get; set; }

    public int LastCycleSpoolAttempted { get; set; }

    public int LastCycleSpoolFlushed { get; set; }

    public int LastCycleSpoolFailed { get; set; }

    public AgentProcessRuntimeStatus? Process { get; set; }

    public List<AgentChannelRuntimeStatus> Channels { get; set; } = [];
}

public sealed class AgentProcessRuntimeStatus
{
    public int ProcessId { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public string CollectedUtc { get; set; } = string.Empty;

    public string ProcessStartedUtc { get; set; } = string.Empty;

    public long UptimeSeconds { get; set; }

    public long WorkingSetBytes { get; set; }

    public long PeakWorkingSetBytes { get; set; }

    public long PrivateMemoryBytes { get; set; }

    public long PagedMemoryBytes { get; set; }

    public long VirtualMemoryBytes { get; set; }

    public int HandleCount { get; set; }

    public int ThreadCount { get; set; }

    public double TotalProcessorTimeSeconds { get; set; }

    public long? ManagedHeapBytes { get; set; }

    public long? ManagedCommittedBytes { get; set; }
}

public static class AgentProcessStatusSampler
{
    public static AgentProcessRuntimeStatus CaptureCurrentProcess(DateTimeOffset agentStartedUtc)
    {
        using var process = Process.GetCurrentProcess();
        return Capture(process, agentStartedUtc, includeManagedMemory: true);
    }

    public static AgentProcessRuntimeStatus? TryCaptureByProcessId(int processId)
    {
        if (processId <= 0)
        {
            return null;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            var processStartedUtc = process.StartTime.ToUniversalTime();
            return Capture(process, processStartedUtc, includeManagedMemory: false);
        }
        catch
        {
            return null;
        }
    }

    private static AgentProcessRuntimeStatus Capture(Process process, DateTimeOffset startedUtc, bool includeManagedMemory)
    {
        process.Refresh();
        var nowUtc = DateTimeOffset.UtcNow;
        var gcMemory = includeManagedMemory ? GC.GetGCMemoryInfo() : default;

        return new AgentProcessRuntimeStatus
        {
            ProcessId = process.Id,
            ProcessName = process.ProcessName,
            CollectedUtc = nowUtc.ToString("O"),
            ProcessStartedUtc = startedUtc.ToString("O"),
            UptimeSeconds = Math.Max(0, (long)(nowUtc - startedUtc).TotalSeconds),
            WorkingSetBytes = process.WorkingSet64,
            PeakWorkingSetBytes = process.PeakWorkingSet64,
            PrivateMemoryBytes = process.PrivateMemorySize64,
            PagedMemoryBytes = process.PagedMemorySize64,
            VirtualMemoryBytes = process.VirtualMemorySize64,
            HandleCount = process.HandleCount,
            ThreadCount = process.Threads.Count,
            TotalProcessorTimeSeconds = Math.Round(process.TotalProcessorTime.TotalSeconds, 3),
            ManagedHeapBytes = includeManagedMemory ? GC.GetTotalMemory(forceFullCollection: false) : null,
            ManagedCommittedBytes = includeManagedMemory ? gcMemory.TotalCommittedBytes : null,
        };
    }
}

public sealed class AgentChannelRuntimeStatus
{
    public string Name { get; set; } = string.Empty;

    public string RoutePath { get; set; } = string.Empty;

    public string Status { get; set; } = "idle";

    public long LastRecordIdBefore { get; set; }

    public long LastRecordIdAfter { get; set; }

    public int EventsRead { get; set; }

    public int EventsSent { get; set; }

    public string Error { get; set; } = string.Empty;
}

public sealed class SpoolFlushResult
{
    public int Attempted { get; set; }

    public int Flushed { get; set; }

    public int Failed { get; set; }
}
