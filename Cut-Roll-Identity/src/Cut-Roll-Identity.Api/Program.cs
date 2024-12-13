using Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplication;
using Cut_Roll_Identity.Api.Common.Extensions.WebApplicationBuilder;

var builder = WebApplication.CreateBuilder(args);

builder.SetupVariables();
builder.InitMessageBroker();

builder.Services.InitAspnetIdentity(builder.Configuration);
builder.Services.InitAuth(builder.Configuration);
builder.Services.InitSwagger();
builder.Services.InitCors();


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


app.UseSwagger();
app.UseSwaggerUI();

app.MapControllers();

app.UseCors("AllowAllOrigins");

app.UseAuthentication();
app.UseAuthorization();


app.Run();
