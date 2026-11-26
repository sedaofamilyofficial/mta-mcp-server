using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace MtaDebugCompanionMcp.Common;

public sealed class GatewaySecurity
{
    public byte[] Authorization { get; }
    public string ApiKey { get; }
    public string Password { get; }
    private readonly Dictionary<string, Dictionary<string, bool>> actions;
    public GatewaySecurity()
    {
        var directory = Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY")
            ?? throw new InvalidOperationException("Missing service credentials");
        string Read(string name)
        {
            var value = File.ReadAllText(Path.Combine(directory, name)).Trim();
            if (!Regex.IsMatch(value, "\\A[a-f0-9]{64}\\z")) throw new InvalidOperationException("Invalid service credential");
            return value;
        }
        var bearer = Read("bearer");
        ApiKey = Read("api-key"); Password = Read("password");
        if (bearer == ApiKey || bearer == Password || ApiKey == Password)
            throw new InvalidOperationException("Service credentials must be independent");
        Authorization = Encoding.ASCII.GetBytes("Bearer " + bearer);
        using var policy = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "policy.json")));
        actions = policy.RootElement.GetProperty("actions").Deserialize<Dictionary<string, Dictionary<string, bool>>>()
            ?? throw new InvalidOperationException("Invalid operator policy");
    }
    public bool Authorize(string header) => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(header), Authorization);
    public bool Allows(string name, string action) => actions.TryGetValue(name, out var grant) && grant.TryGetValue(action, out var allowed) && allowed;
    public static bool ResourceName(string? name) => name is not null && Regex.IsMatch(name, "\\A[A-Za-z0-9_-]{1,64}\\z");
    public static int Port(string variable, int fallback)
    {
        var raw = Environment.GetEnvironmentVariable(variable);
        if (raw is null) return fallback;
        if (!int.TryParse(raw, out var port) || port < 1024 || port > 65535) throw new InvalidOperationException("Invalid loopback port");
        return port;
    }
}
