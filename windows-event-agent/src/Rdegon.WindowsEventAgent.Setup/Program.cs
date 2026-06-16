namespace Rdegon.WindowsEventAgent.Setup;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            return await SetupApp.RunAsync(args, CancellationToken.None);
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
