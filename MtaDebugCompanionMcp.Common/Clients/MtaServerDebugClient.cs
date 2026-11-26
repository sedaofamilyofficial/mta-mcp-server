using System.Net.Http.Json;
using System.Text.Json;
using ModelContextProtocol;

namespace MtaDebugCompanionMcp.Common.Clients;

public sealed class MtaServerDebugClient(HttpClient http, GatewaySecurity security)
{
    public Task<string> Status(string? resource, CancellationToken ct)
    {
        if (resource is not null && !GatewaySecurity.ResourceName(resource)) throw new McpException("Invalid resource name");
        return Send(resource is null ? new { operation = "status" } : (object)new { operation = "status", resource }, ct);
    }
    public Task<string> Logs(int lines, CancellationToken ct)
    {
        if (lines < 1 || lines > 50) throw new McpException("Log limit must be 1-50");
        return Send(new { operation = "logs", lines }, ct);
    }
    public Task<string> Action(string name, string action, CancellationToken ct)
    {
        if (!GatewaySecurity.ResourceName(name) || action is not ("start" or "stop" or "restart")) throw new McpException("Invalid action");
        if (!security.Allows(name, action)) throw new McpException("Action denied by operator policy");
        return Send(new { operation = "action", resource = name, action }, ct);
    }
    private async Task<string> Send(object body, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "pulsar_debug_gateway/")
            { Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json") };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(4));
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode) throw new McpException("MTA request denied or unavailable");
            await response.Content.LoadIntoBufferAsync(65536, timeout.Token);
            var value = await response.Content.ReadAsStringAsync(ct);
            using var parsed = JsonDocument.Parse(value);
            if (parsed.RootElement.ValueKind != JsonValueKind.Object) throw new McpException("Invalid MTA response");
            return value;
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or JsonException)
        {
            throw new McpException("MTA diagnostics unavailable");
        }
    }
}