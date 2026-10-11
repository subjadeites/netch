using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Netch;
using Netch.Controllers;
using Netch.Interops;
using Netch.Models;

if (args.Length != 1)
    throw new ArgumentException("Pass the absolute path to the freshly built AioDNS shared library.");
var library = NativeLibrary.Load(Path.GetFullPath(args[0]));
NativeLibrary.SetDllImportResolver(typeof(AioDNS).Assembly, (name, _, _) => name == "aiodns.bin" ? library : IntPtr.Zero);

var originalDirectory = Directory.GetCurrentDirectory();
var tempDirectory = Path.Combine(Path.GetTempPath(), "aiodns-测试-" + Guid.NewGuid());
Directory.CreateDirectory(tempDirectory);
Directory.SetCurrentDirectory(tempDirectory);
var controller = new DNSController();
try
{
    var ruleFile = Path.GetFullPath(Constants.AioDnsRuleFile);
    Directory.CreateDirectory(Path.GetDirectoryName(ruleFile)!);
    File.WriteAllText(ruleFile, "example.cn.\n");

    Require(AioDNS.Dial(AioDNS.NameList.TYPE_REST, ""), "reset returned false");
    Require(!AioDNS.Dial((AioDNS.NameList)(-1), ""), "invalid 32-bit enum returned true");
    Require(!AioDNS.Init(), "unconfigured native init returned true");
    Require(!AioDNS.Dial(AioDNS.NameList.TYPE_CDNS, "invalid"), "invalid upstream returned true");

    // Exercise the actual controller's fail-fast path, not a duplicate wrapper.
    Global.Settings.AioDNS.ChinaDNS = "invalid";
    try
    {
        await controller.StartAsync();
        throw new Exception("controller ignored invalid configuration");
    }
    catch (MessageException e) when (e.Message.Contains("TYPE_CDNS")) { }

    // Keep a bound, non-listening TCP socket so the upstream deterministically
    // refuses connections, without relying on public DNS or an unowned port.
    using var unavailable = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    unavailable.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    var upstream = $"tcp://{unavailable.LocalEndPoint}";
    Global.Settings.AioDNS.ChinaDNS = upstream;
    Global.Settings.AioDNS.OtherDNS = upstream;

    // A Unicode filename crosses the actual UTF-8 C.GoString boundary.
    Require(AioDNS.Dial(AioDNS.NameList.TYPE_LISN, "127.0.0.1:0"), "listen address rejected");
    Require(AioDNS.Dial(AioDNS.NameList.TYPE_CDNS, upstream), "China upstream rejected");
    Require(AioDNS.Dial(AioDNS.NameList.TYPE_ODNS, upstream), "Other upstream rejected");
    Require(AioDNS.Dial(AioDNS.NameList.TYPE_LIST, Path.Combine(tempDirectory, "不存在.conf")), "rule path rejected");
    Require(!AioDNS.Init(), "missing rule file did not return false");

    for (var i = 0; i < 20; i++)
    {
        Global.Settings.AioDNS.ListenPort = FreePort();
        await controller.StartAsync();
        await Query("1.0.0.127.in-addr.arpa", 12, expectedRcode: 0, expectedAnswers: 1);
        await Query("example.org", 1, expectedRcode: 2, expectedAnswers: 0);
        await controller.StopAsync();
        await controller.StopAsync();
    }

    using (var occupied = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)))
    {
        Global.Settings.AioDNS.ListenPort = (ushort)((IPEndPoint)occupied.Client.LocalEndPoint!).Port;
        try
        {
            await controller.StartAsync();
            throw new Exception("controller started despite occupied UDP port");
        }
        catch (MessageException e) when (e.Message.Contains("AioDNS start failed")) { }
        // A failed UDP bind must roll back the TCP bind.
        var tcp = new TcpListener(IPAddress.Loopback, Global.Settings.AioDNS.ListenPort);
        tcp.Start();
        tcp.Stop();
    }
    await controller.StartAsync();
    await controller.StopAsync();
    Console.WriteLine("PASS: managed/native ABI, configuration errors, DNS responses, 20 start/stop cycles, and bind rollback");
}
finally
{
    await controller.StopAsync();
    Directory.SetCurrentDirectory(originalDirectory);
    Directory.Delete(tempDirectory, true);
    // Go c-shared libraries must remain loaded until process exit.
}

static void Require(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static ushort FreePort()
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = (ushort)((IPEndPoint)listener.LocalEndpoint).Port;
    listener.Stop();
    return port;
}

static async Task Query(string domain, ushort type, int expectedRcode, int expectedAnswers)
{
    var query = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    foreach (var label in domain.Split('.'))
    {
        query.Add((byte)label.Length);
        query.AddRange(Encoding.ASCII.GetBytes(label));
    }
    query.AddRange(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
    using var client = new UdpClient();
    client.Connect(IPAddress.Loopback, Global.Settings.AioDNS.ListenPort);
    await client.SendAsync(query.ToArray(), query.Count);
    var response = (await client.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5))).Buffer;
    Require(response.Length >= 12, "short DNS response");
    Require(BinaryPrimitives.ReadUInt16BigEndian(response) == 0x1234, "DNS response ID mismatch");
    Require((response[3] & 15) == expectedRcode, "wrong DNS response code");
    Require(BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6)) == expectedAnswers, "wrong DNS answer count");
}

namespace Netch
{
    // Only application state is substituted. The interop and controller sources
    // compiled above are exactly the files used by the WinForms application.
    public static class Global
    {
        public static InteropSettings Settings { get; } = new();
    }

    public sealed class InteropSettings
    {
        public AioDNSConfig AioDNS { get; } = new();
    }
}
