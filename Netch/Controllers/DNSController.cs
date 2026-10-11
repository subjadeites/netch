using Netch.Interfaces;
using Netch.Models;
using static Netch.Interops.AioDNS;

namespace Netch.Controllers;

public class DNSController : IController
{
    public string Name => "DNS Service";

    public async Task StartAsync()
    {
        var aioDnsConfig = Global.Settings.AioDNS;

        Configure(NameList.TYPE_REST, "");
        Configure(NameList.TYPE_LIST, Path.GetFullPath(Constants.AioDnsRuleFile));
        // TODO remove ListenPort setting
        Configure(NameList.TYPE_LISN, $"127.0.0.1:{aioDnsConfig.ListenPort}");
        Configure(NameList.TYPE_CDNS, aioDnsConfig.ChinaDNS);
        Configure(NameList.TYPE_ODNS, aioDnsConfig.OtherDNS);

        Log.Information("[aiodns] Initializing DNS service");
        if (!await InitAsync())
            throw new MessageException("AioDNS start failed.");
    }

    private static void Configure(NameList name, string value)
    {
        if (!Dial(name, value))
            throw new MessageException($"AioDNS rejected configuration {name}: {value}");
    }

    public Task StopAsync()
    {
        return FreeAsync();
    }
}
