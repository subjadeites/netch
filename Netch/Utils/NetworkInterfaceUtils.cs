using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using Windows.Win32;
using Windows.Win32.NetworkManagement.IpHelper;
using Serilog;
using Netch.Models;

namespace Netch.Utils;

public static class NetworkInterfaceUtils
{
    public static NetworkInterface GetBest(AddressFamily addressFamily = AddressFamily.InterNetwork)
    {
        string ipAddress;
        switch (addressFamily)
        {
            case AddressFamily.InterNetwork:
                ipAddress = "114.114.114.114";
                break;
            case AddressFamily.InterNetworkV6:
                throw new NotImplementedException();
            default:
                throw new InvalidOperationException();
        }

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

    public static void SetInterfaceAdminStatus(int interfaceIndex, bool enable)
    {
        MIB_IF_ROW2 row = default;
        row.InterfaceIndex = (uint)interfaceIndex;

        var result = PInvoke.GetIfEntry2(ref row);
        if (result != 0)
        {
            Log.Warning("GetIfEntry2({InterfaceIndex}) failed with {Result}", interfaceIndex, result);
            return;
        }

        var target = enable ? NET_IF_ADMIN_STATUS.NET_IF_ADMIN_STATUS_UP : NET_IF_ADMIN_STATUS.NET_IF_ADMIN_STATUS_DOWN;
        if (row.AdminStatus == target)
            return;

        row.AdminStatus = target;
        result = PInvoke.SetIfEntry2(ref row);
        if (result != 0)
            Log.Warning("SetIfEntry2({InterfaceIndex}) failed with {Result}", interfaceIndex, result);
    }

    public static bool WaitForOperStatus(int interfaceIndex, IF_OPER_STATUS status, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            MIB_IF_ROW2 row = default;
            row.InterfaceIndex = (uint)interfaceIndex;

            if (PInvoke.GetIfEntry2(ref row) == 0 && row.OperStatus == status)
                return true;

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