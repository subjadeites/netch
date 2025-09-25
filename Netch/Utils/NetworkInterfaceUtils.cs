using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using Serilog;
using Windows.Win32;
using Windows.Win32.NetworkManagement.IpHelper;
using Serilog;
using Netch.Models;

namespace Netch.Utils;

public static class NetworkInterfaceUtils
{
    public static NetworkInterface GetBest(AddressFamily addressFamily = AddressFamily.InterNetwork)
    {
        string ipAddress = addressFamily switch
        {
            AddressFamily.InterNetwork => "114.114.114.114",
            AddressFamily.InterNetworkV6 => throw new NotImplementedException(),
            _ => throw new InvalidOperationException()
        };

        if (PInvoke.GetBestRoute(BitConverter.ToUInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0), 0, out var route) != 0)
            throw new MessageException("GetBestRoute 搜索失败");

        return Get((int)route.dwForwardIfIndex);
    }

    public static NetworkInterface Get(int interfaceIndex)
    {
        return NetworkInterface.GetAllNetworkInterfaces().First(n => n.GetIndex() == interfaceIndex);
    }

    public static NetworkInterface Get(Func<NetworkInterface, bool> expression)
    {
        return NetworkInterface.GetAllNetworkInterfaces().First(expression);
    }

    public static void SetInterfaceMetric(int interfaceIndex, int? metric = null)
    {
        var arguments = $"interface ip set interface {interfaceIndex} ";
        if (metric != null)
            arguments += $"metric={metric} ";

        Process.Start(new ProcessStartInfo("netsh.exe", arguments)
        {
            UseShellExecute = false,
            Verb = "runas"
        })!.WaitForExit();
    }

    public static bool TrySetInterfaceAdminStatus(int interfaceIndex, bool enable, TimeSpan? waitTimeout = null,
        TimeSpan? commandTimeout = null)
    {
        string? adapterName = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(ni => ni.GetIndex() == interfaceIndex)?.Name;

        if (adapterName == null)
        {
            Log.Warning("Interface {InterfaceIndex} not found while toggling admin state", interfaceIndex);
            return false;
        }

        var arguments =
            $"interface set interface name=\"{adapterName}\" admin={(enable ? "ENABLED" : "DISABLED")}";
        var timeout = (int)(commandTimeout ?? TimeSpan.FromSeconds(5)).TotalMilliseconds;

        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("netsh.exe", arguments)
                {
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    Verb = "runas"
                }
            };

            if (!process.Start())
            {
                Log.Warning("Failed to launch netsh when toggling interface {InterfaceIndex}", interfaceIndex);
                return false;
            }

            if (!process.WaitForExit(timeout))
            {
                try
                {
                    process.Kill(true);
                }
                catch
                {
                    // ignored
                }

                Log.Warning("netsh timed out while changing admin state of interface {InterfaceIndex}", interfaceIndex);
                return false;
            }

            if (process.ExitCode != 0)
            {
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                Log.Warning(
                    "netsh failed to change admin state of interface {InterfaceIndex}. Exit {ExitCode}. Output: {Output}. Error: {Error}",
                    interfaceIndex, process.ExitCode, output, error);
                return false;
            }
        }
        catch (Exception e)
        {
            Log.Warning(e, "Exception while changing admin state of interface {InterfaceIndex}", interfaceIndex);
            return false;
        }

        if (waitTimeout.HasValue)
        {
            var targetStatus = enable ? OperationalStatus.Up : OperationalStatus.Down;
            var treatMissingAsMatch = !enable;

            if (!WaitForOperationalStatus(interfaceIndex, targetStatus, waitTimeout.Value, treatMissingAsMatch))
                Log.Warning("Timed out waiting for interface {InterfaceIndex} to reach {Status}", interfaceIndex, targetStatus);
        }

        return true;
    }

    public static bool WaitForOperationalStatus(int interfaceIndex, OperationalStatus status, TimeSpan timeout,
        bool treatMissingAsMatch = false)

    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            var adapter = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(ni => ni.GetIndex() == interfaceIndex);

            if (adapter == null)
            {
                if (treatMissingAsMatch)
                    return true;
            }
            else if (adapter.OperationalStatus == status)
            {
                return true;
            }


            Thread.Sleep(TimeSpan.FromMilliseconds(200));
        }

        return false;
    }
}

public static class NetworkInterfaceExtension
{
    public static int GetIndex(this NetworkInterface ni)
    {
        var ipProperties = ni.GetIPProperties();
        if (ni.Supports(NetworkInterfaceComponent.IPv4))
            return ipProperties.GetIPv4Properties().Index;

        if (ni.Supports(NetworkInterfaceComponent.IPv6))
            return ipProperties.GetIPv6Properties().Index;

        throw new Exception();
    }

    public static void SetDns(this NetworkInterface ni, string primaryDns, string? secondDns = null)
    {
        void VerifyDns(ref string s)
        {
            s = s.Trim();
            if (primaryDns.IsNullOrEmpty())
                throw new ArgumentException("DNS format invalid", nameof(primaryDns));
        }

        VerifyDns(ref primaryDns);
        if (secondDns != null)
            VerifyDns(ref primaryDns);

        var wmi = new ManagementClass("Win32_NetworkAdapterConfiguration");
        var mos = wmi.GetInstances().Cast<ManagementObject>();

        var mo = mos.First(m => m["Description"].ToString() == ni.Description);

        var dns = new[] { primaryDns };
        if (secondDns != null)
            dns = dns.Append(secondDns).ToArray();

        var inPar = mo.GetMethodParameters("SetDNSServerSearchOrder");
        inPar["DNSServerSearchOrder"] = dns;

        mo.InvokeMethod("SetDNSServerSearchOrder", inPar, null);
    }
}
