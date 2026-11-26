using MtaDebugCompanionMcp.Common;
using MtaDebugCompanionMcp.Common.Tools;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders(); // Never log request bodies, credentials or engine errors.
builder.WebHost.UseUrls($"http://127.0.0.1:{GatewaySecurity.Port("PULSAR_GATEWAY_PORT", 5278)}");
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 8192);
var security = new GatewaySecurity();
builder.Services.AddMtaDebugCompanionMcpServices(security);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
        RateLimitPartition.GetFixedWindowLimiter("gateway", _ => new FixedWindowRateLimiterOptions
        { PermitLimit = 60, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
builder.Services.AddMcpServer().WithToolsFromAssembly(typeof(MtaDebugCompanionTools).Assembly)
    .WithHttpTransport(options => options.Stateless = true);
var app = builder.Build();
app.Use(async (context, next) =>
{
    context.Response.Headers.CacheControl = "no-store";
    if (!security.Authorize(context.Request.Headers.Authorization.ToString()))
    {
        context.Response.StatusCode = 401; context.Response.Headers.WWWAuthenticate = "Bearer"; return;
    }
    var origin = context.Request.Headers.Origin.ToString();
    if (origin.Length != 0 && origin != "https://piz.deez.nz") { context.Response.StatusCode = 403; return; }
    if (context.Request.Path != "/mcp") { context.Response.StatusCode = 404; return; }
    await next(context);
});
app.UseRateLimiter();
app.MapMcp("/mcp");
app.Run();
