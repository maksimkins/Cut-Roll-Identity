using Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplication;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplicationBuilder;
using Cut_Roll_Identity.Api.Common.Extensions.Controllers;

var builder = WebApplication.CreateBuilder(args);

// Configure Kestrel
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ListenAnyIP(80);
});

// Setup variables
builder.SetupVariables();

// Configure services
builder.Services.InitAspNetIdentity();
builder.Services.InitAuth(builder.Configuration);
builder.Services.InitCors();
builder.Services.InitSwagger();
builder.Services.RegisterDependencyInjection();
builder.Services.RegisterConfigureBlobStorage();
builder.Services.ConfigureEmailSender();
builder.Services.ConfigureMessageBroker();
builder.Services.ConfigureRedirectOption();

var app = builder.Build();

// Configure forwarded headers for Traefik
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
    RequireHeaderSymmetry = false,
    ForwardedForHeaderName = "X-Original-For",
    ForwardedProtoHeaderName = "X-Original-Proto",
    ForwardedHostHeaderName = "X-Original-Host"
});

// Configure HTTPS redirection
app.UseHttpsRedirection();

// Configure CORS
app.UseCors();

// Configure authentication and authorization
app.UseAuthentication();
app.UseAuthorization();

// Configure Swagger
app.InitSwagger();

// Configure routing
app.MapControllers();

// Setup database and admin user
await app.UpdateDbAsync();
await app.SetupRolesAsync();
await app.SetupAdminAsync();

// Custom middleware for debugging OAuth requests
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value;
    
    // Log OAuth-related requests
    if (path?.Contains("Authentication") == true || path?.Contains("signin-google") == true)
    {
        Console.WriteLine($"=== OAuth Request Debug ===");
        Console.WriteLine($"Path: {context.Request.Path}");
        Console.WriteLine($"Method: {context.Request.Method}");
        Console.WriteLine($"Scheme: {context.Request.Scheme}");
        Console.WriteLine($"Host: {context.Request.Host}");
        Console.WriteLine($"QueryString: {context.Request.QueryString}");
        Console.WriteLine($"X-Forwarded-Proto: {context.Request.Headers["X-Forwarded-Proto"]}");
        Console.WriteLine($"X-Original-Proto: {context.Request.Headers["X-Original-Proto"]}");
        Console.WriteLine($"X-Forwarded-Host: {context.Request.Headers["X-Forwarded-Host"]}");
        Console.WriteLine($"X-Original-Host: {context.Request.Headers["X-Original-Host"]}");
    }
    
    await next();
});

app.Run();
