using Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplication;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplicationBuilder;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(80); 
});

builder.SetupVariables();
builder.ConfigureEmailSender();
builder.ConfigureRedirectOption();
builder.ConfigureMessageBroker();

builder.Services.InitAspnetIdentity(builder.Configuration);
builder.Services.InitAuth(builder.Configuration);

builder.Services.ConfigureExternalCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None; 
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.Domain = null; // Allow any domain
    options.Cookie.Path = "/";
});

// Configure authentication cookies for better Traefik compatibility
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.Domain = null;
    options.Cookie.Path = "/";
});

builder.Services.InitSwagger();
builder.Services.InitCors();
builder.Services.RegisterDependencyInjection();
builder.Services.RegisterConfigureBlobStorage(builder.Configuration);

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var app = builder.Build();

await app.UpdateDbAsync();
await app.SetupRolesAsync();
await app.SetupAdminAsync(builder.Configuration);

var forwardedHeaderOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
};
forwardedHeaderOptions.KnownNetworks.Clear();
forwardedHeaderOptions.KnownProxies.Clear();

app.UseForwardedHeaders(forwardedHeaderOptions);

// Debug middleware to log request details
app.Use(async (ctx, next) => 
{ 
    ctx.Request.Scheme = "https"; 
    
    // Log request details for debugging
    if (ctx.Request.Path.StartsWithSegments("/Authentication/GoogleLoginCallback"))
    {
        Console.WriteLine($"OAuth Callback Request:");
        Console.WriteLine($"  Path: {ctx.Request.Path}");
        Console.WriteLine($"  QueryString: {ctx.Request.QueryString}");
        Console.WriteLine($"  Scheme: {ctx.Request.Scheme}");
        Console.WriteLine($"  Host: {ctx.Request.Host}");
        Console.WriteLine($"  Headers: {string.Join(", ", ctx.Request.Headers.Select(h => $"{h.Key}={h.Value}"))}");
    }
    
    await next(); 
});


app.UseSwagger();
app.UseSwaggerUI();

app.UseRouting();
app.UseCors("AllowAllOrigins");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();


app.Run();
