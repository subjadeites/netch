using System.Runtime.InteropServices;
using System.Text;

namespace Netch.Interops;

public static class AioDNS
{
    private const string aiodns_bin = "aiodns.bin";

    public static bool Dial(NameList name, string value)
    {
        Log.Verbose($"[aiodns] Dial {name}: {value}");
        return aiodns_dial(name, Encoding.UTF8.GetBytes(value));
    }

    public static Task<bool> InitAsync()
    {
        return Task.Run(Init);
    }

    public static async Task FreeAsync()
    {
        var tcs = new TaskCompletionSource<bool>();
        new Thread(() =>
        {
            try
            {
                Free();
                tcs.TrySetResult(true);
            }
            catch (Exception e)
            {
                tcs.TrySetException(e);
            }
        })
        {
            IsBackground = true
        }.Start();

        var completed = await Task.WhenAny(tcs.Task, Task.Delay(TimeSpan.FromSeconds(5))).ConfigureAwait(false);
        if (completed != tcs.Task)
        {
            Log.Warning("[aiodns] free timed out");
            return;
        }

        await tcs.Task.ConfigureAwait(false);
    }

    [DllImport(aiodns_bin, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool aiodns_dial(NameList name, byte[] value);

    [DllImport(aiodns_bin, EntryPoint = "aiodns_init", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool Init();

    [DllImport(aiodns_bin, EntryPoint = "aiodns_free", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Free();

    public enum NameList
    {
        TYPE_REST,
        TYPE_LIST,
        TYPE_LISN,
        TYPE_CDNS,
        TYPE_ODNS
    }
}