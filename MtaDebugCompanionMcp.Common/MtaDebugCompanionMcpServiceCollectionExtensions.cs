using Microsoft.Extensions.DependencyInjection;
using MtaDebugCompanionMcp.Common.Clients;
using System.Net.Http.Headers;
using System.Text;

namespace MtaDebugCompanionMcp.Common;

public static class MtaDebugCompanionMcpServiceCollectionExtensions
{
    public static IServiceCollection AddMtaDebugCompanionMcpServices(this IServiceCollection services, GatewaySecurity security)
    {
        services.AddSingleton(security);
        services.AddHttpClient<MtaServerDebugClient>(http =>
        {
            http.BaseAddress = new Uri($"http://127.0.0.1:{GatewaySecurity.Port("PULSAR_MTA_PORT", 22005)}/");
            http.Timeout = TimeSpan.FromSeconds(4);
            http.DefaultRequestHeaders.Add("api-key", security.ApiKey);
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.ASCII.GetBytes("pulsar_debug_gateway:" + security.Password)));
        }).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false });
        return services;
    }
}