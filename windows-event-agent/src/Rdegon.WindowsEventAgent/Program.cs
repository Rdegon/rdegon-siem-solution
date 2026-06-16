using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace Rdegon.WindowsEventAgent;

public static class Program
{
    public static async Task Main(string[] args)
    {
        var runtimeMode = AgentRuntimeMode.Parse(args);
        var builder = Host.CreateApplicationBuilder(args);

        if (runtimeMode.RunAsWindowsService)
        {
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "Rdegon Windows Event Agent";
            });
        }
        else
        {
            builder.Logging.AddSimpleConsole(options =>
            {
                options.SingleLine = true;
                options.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
            });
        }

        builder.Configuration
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
            .AddEnvironmentVariables(prefix: "RDEGON_WINDOWS_AGENT_");

        builder.Logging.AddEventLog(settings =>
        {
            settings.SourceName = "Rdegon.WindowsEventAgent";
            settings.LogName = "Application";
        });

        builder.Services
            .AddOptions<AgentOptions>()
            .Bind(builder.Configuration.GetSection("Agent"))
            .PostConfigure(options =>
            {
                if (string.IsNullOrWhiteSpace(options.InstanceName)
                    || options.InstanceName.Equals("AUTO_MACHINE_NAME", StringComparison.OrdinalIgnoreCase))
                {
                    options.InstanceName = Environment.MachineName;
                }

                if (options.Channels.Count == 0)
                {
                    options.Channels = AgentOptions.CreateDefaultChannels();
                    return;
                }

                options.Channels = options.Channels
                    .Where(channel => !string.IsNullOrWhiteSpace(channel.Name) && !string.IsNullOrWhiteSpace(channel.RoutePath))
                    .GroupBy(channel => $"{channel.Name}|{channel.RoutePath}", StringComparer.OrdinalIgnoreCase)
                    .Select(group => group.First())
                    .ToList();
            })
            .ValidateDataAnnotations()
            .Validate(options => options.Channels.Count > 0, "At least one Windows event channel must be configured.")
            .ValidateOnStart();

        builder.Services.AddSingleton(runtimeMode);
        builder.Services.AddSingleton<BookmarkStore>();
        builder.Services.AddSingleton<DiskSpoolQueue>();
        builder.Services.AddSingleton<RuntimeStatusStore>();
        builder.Services.AddSingleton<WindowsEventPayloadFactory>();

        builder.Services
            .AddHttpClient<IngestHttpClient>((serviceProvider, client) =>
            {
                var options = serviceProvider.GetRequiredService<IOptions<AgentOptions>>().Value;
                client.BaseAddress = new Uri(options.BaseUrl.TrimEnd('/') + "/");
                client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);

                if (!string.IsNullOrWhiteSpace(options.SharedSecret))
                {
                    client.DefaultRequestHeaders.Remove("x-rdegon-ingest-secret");
                    client.DefaultRequestHeaders.Add("x-rdegon-ingest-secret", options.SharedSecret);
                }
            })
            .ConfigurePrimaryHttpMessageHandler(serviceProvider =>
            {
                var options = serviceProvider.GetRequiredService<IOptions<AgentOptions>>().Value;
                var handler = new HttpClientHandler();

                if (options.AllowInvalidServerCertificate)
                {
                    handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                }

                return handler;
            });

        builder.Services.AddHostedService<WindowsEventCollectorService>();

        var host = builder.Build();

        if (runtimeMode.PrintConfig)
        {
            var options = host.Services.GetRequiredService<IOptions<AgentOptions>>().Value;
            var payload = JsonSerializer.Serialize(options, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
            Console.WriteLine(payload);
            return;
        }

        if (runtimeMode.PrintStatusPath)
        {
            var statusStore = host.Services.GetRequiredService<RuntimeStatusStore>();
            Console.WriteLine(statusStore.StatusPath);
            return;
        }

        await host.RunAsync();
    }
}
