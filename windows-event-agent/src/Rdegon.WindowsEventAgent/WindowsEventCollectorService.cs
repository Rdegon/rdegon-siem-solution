using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Rdegon.WindowsEventAgent;

public sealed class WindowsEventCollectorService : BackgroundService
{
    private readonly DateTimeOffset _startedAtUtc = DateTimeOffset.UtcNow;
    private readonly AgentOptions _options;
    private readonly BookmarkStore _bookmarkStore;
    private readonly DiskSpoolQueue _spoolQueue;
    private readonly RuntimeStatusStore _runtimeStatusStore;
    private readonly WindowsEventPayloadFactory _payloadFactory;
    private readonly IngestHttpClient _ingestHttpClient;
    private readonly AgentRuntimeMode _runtimeMode;
    private readonly IHostApplicationLifetime _applicationLifetime;
    private readonly ILogger<WindowsEventCollectorService> _logger;
    private DateTimeOffset? _lastSuccessfulDeliveryUtc;
    private string _lastError = string.Empty;

    public WindowsEventCollectorService(
        IOptions<AgentOptions> options,
        BookmarkStore bookmarkStore,
        DiskSpoolQueue spoolQueue,
        RuntimeStatusStore runtimeStatusStore,
        WindowsEventPayloadFactory payloadFactory,
        IngestHttpClient ingestHttpClient,
        AgentRuntimeMode runtimeMode,
        IHostApplicationLifetime applicationLifetime,
        ILogger<WindowsEventCollectorService> logger)
    {
        _options = options.Value;
        _bookmarkStore = bookmarkStore;
        _spoolQueue = spoolQueue;
        _runtimeStatusStore = runtimeStatusStore;
        _payloadFactory = payloadFactory;
        _ingestHttpClient = ingestHttpClient;
        _runtimeMode = runtimeMode;
        _applicationLifetime = applicationLifetime;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Rdegon Windows Event Agent started for {InstanceName}", _options.InstanceName);
        await WriteStatusAsync(
            status: "starting",
            cycleStartedUtc: null,
            cycleCompletedUtc: null,
            channelStatuses: [],
            spoolFlushResult: new SpoolFlushResult(),
            cancellationToken: stoppingToken);

        await RunOnceAsync(stoppingToken);

        if (_runtimeMode.RunOnce)
        {
            _logger.LogInformation("Run-once mode completed; stopping host");
            _applicationLifetime.StopApplication();
            return;
        }

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, _options.PollIntervalSeconds)));
        while (!stoppingToken.IsCancellationRequested && await timer.WaitForNextTickAsync(stoppingToken))
        {
            await RunOnceAsync(stoppingToken);
        }
    }

    private async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        var cycleStartedUtc = DateTimeOffset.UtcNow;
        var channelStatuses = new List<AgentChannelRuntimeStatus>();
        var spoolFlushResult = await FlushSpoolAsync(cancellationToken);

        foreach (var channel in _options.Channels.Where(channel => channel.Enabled))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var lastRecordId = await _bookmarkStore.GetLastRecordIdAsync(channel.Name, cancellationToken);
            var readResult = await _payloadFactory.ReadNewEventsAsync(channel, lastRecordId, cancellationToken);
            var channelStatus = new AgentChannelRuntimeStatus
            {
                Name = channel.Name,
                RoutePath = readResult.RoutePath,
                LastRecordIdBefore = lastRecordId,
                LastRecordIdAfter = readResult.NewestRecordId,
                EventsRead = readResult.Events.Count,
                EventsSent = 0,
                Status = "idle",
            };

            if (readResult.Events.Count == 0 || readResult.NewestRecordId <= lastRecordId)
            {
                channelStatuses.Add(channelStatus);
                continue;
            }

            try
            {
                await _ingestHttpClient.SendBatchAsync(readResult.RoutePath, readResult.Events, cancellationToken);
                _logger.LogInformation(
                    "Sent {EventCount} events from {ChannelName} to {RoutePath}",
                    readResult.Events.Count,
                    channel.Name,
                    readResult.RoutePath);

                await _bookmarkStore.SaveLastRecordIdAsync(channel.Name, readResult.NewestRecordId, cancellationToken);
                _lastSuccessfulDeliveryUtc = DateTimeOffset.UtcNow;
                _lastError = string.Empty;
                channelStatus.EventsSent = readResult.Events.Count;
                channelStatus.Status = "sent";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(
                    ex,
                    "Unable to send {EventCount} events from {ChannelName}; writing batch to spool",
                    readResult.Events.Count,
                    channel.Name);

                await _spoolQueue.EnqueueAsync(readResult.RoutePath, readResult.Events, cancellationToken);
                await _bookmarkStore.SaveLastRecordIdAsync(channel.Name, readResult.NewestRecordId, cancellationToken);
                _lastError = ex.Message;
                channelStatus.Status = "spooled";
                channelStatus.Error = ex.Message;
            }

            channelStatuses.Add(channelStatus);
        }

        await WriteStatusAsync(
            status: string.IsNullOrWhiteSpace(_lastError) ? "healthy" : "degraded",
            cycleStartedUtc: cycleStartedUtc,
            cycleCompletedUtc: DateTimeOffset.UtcNow,
            channelStatuses: channelStatuses,
            spoolFlushResult: spoolFlushResult,
            cancellationToken: cancellationToken);
    }

    private async Task<SpoolFlushResult> FlushSpoolAsync(CancellationToken cancellationToken)
    {
        var result = new SpoolFlushResult();
        var pending = await _spoolQueue.GetPendingAsync(cancellationToken);
        result.Attempted = pending.Count;
        foreach (var batch in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _ingestHttpClient.SendBatchAsync(batch.RoutePath, batch.Events, cancellationToken);
                await _spoolQueue.RemoveAsync(batch.FilePath, cancellationToken);
                result.Flushed += 1;
                _lastSuccessfulDeliveryUtc = DateTimeOffset.UtcNow;
                _lastError = string.Empty;
                _logger.LogInformation(
                    "Flushed spooled batch {FileName} with {EventCount} events",
                    Path.GetFileName(batch.FilePath),
                    batch.Events.Count);
            }
            catch (Exception ex)
            {
                result.Failed += 1;
                _lastError = ex.Message;
                _logger.LogWarning(ex, "Unable to flush spooled batch {FileName}; keeping it on disk", Path.GetFileName(batch.FilePath));
                break;
            }
        }

        return result;
    }

    private async Task WriteStatusAsync(
        string status,
        DateTimeOffset? cycleStartedUtc,
        DateTimeOffset? cycleCompletedUtc,
        IReadOnlyCollection<AgentChannelRuntimeStatus> channelStatuses,
        SpoolFlushResult spoolFlushResult,
        CancellationToken cancellationToken)
    {
        var runtimeStatus = new AgentRuntimeStatus
        {
            InstanceName = _options.InstanceName,
            MachineName = Environment.MachineName,
            Status = status,
            StartedUtc = _startedAtUtc.ToString("O"),
            LastCycleStartedUtc = cycleStartedUtc?.ToString("O") ?? string.Empty,
            LastCycleCompletedUtc = cycleCompletedUtc?.ToString("O") ?? string.Empty,
            LastSuccessfulDeliveryUtc = _lastSuccessfulDeliveryUtc?.ToString("O") ?? string.Empty,
            LastError = _lastError,
            PendingSpoolFiles = await _spoolQueue.CountPendingAsync(cancellationToken),
            LastCycleSpoolAttempted = spoolFlushResult.Attempted,
            LastCycleSpoolFlushed = spoolFlushResult.Flushed,
            LastCycleSpoolFailed = spoolFlushResult.Failed,
            StatusPath = _runtimeStatusStore.StatusPath,
            Process = AgentProcessStatusSampler.CaptureCurrentProcess(_startedAtUtc),
            Channels = channelStatuses.ToList(),
        };

        await _runtimeStatusStore.WriteAsync(runtimeStatus, cancellationToken);
    }
}
