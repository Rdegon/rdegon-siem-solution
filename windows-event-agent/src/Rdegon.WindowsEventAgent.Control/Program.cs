namespace Rdegon.WindowsEventAgent.Control;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            return await AgentControlApp.RunAsync(args, Directory.GetCurrentDirectory(), CancellationToken.None);
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }
}
