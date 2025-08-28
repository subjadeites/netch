using System.Runtime.InteropServices;

namespace Netch;

public static class NativeMethods
{
    [DllImport("dnsapi", EntryPoint = "DnsFlushResolverCache")]
    public static extern uint RefreshDNSCache();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    public const uint WAIT_TIMEOUT = 0x00000102;
}