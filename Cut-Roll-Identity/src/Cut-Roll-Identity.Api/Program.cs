using Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplication;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplicationBuilder;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(80); 
});

builder.SetupVariables();
builder.InitMessageBroker();

builder.Services.InitAspnetIdentity(builder.Configuration);
builder.Services.InitAuth(builder.Configuration);
builder.Services.InitSwagger();
builder.Services.InitCors();
builder.Services.ConfigureServices(builder.Configuration);
builder.Services.RegisterDependencyInjection();
builder.Services.RegisterBlobStorage(builder.Configuration);

builder.Services.AddAuthorization();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UpdateDb();
await app.SetupRoles();
await app.SetupAdmin(builder.Configuration);

var forwardedHeaderOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
};
forwardedHeaderOptions.KnownNetworks.Clear();
forwardedHeaderOptions.KnownProxies.Clear();

app.UseForwardedHeaders(forwardedHeaderOptions);

app.UseSwagger();
app.UseSwaggerUI();

app.UseRouting();
app.UseCors("AllowAllOrigins");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();


app.Run();
