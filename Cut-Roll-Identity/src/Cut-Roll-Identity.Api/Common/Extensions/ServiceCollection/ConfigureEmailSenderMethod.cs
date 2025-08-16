namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

using Cut_Roll_Identity.Api.Common.Configurations;
using Cut_Roll_Identity.Core.Common.Options;
using Microsoft.Extensions.Options;

public static class ConfigureEmailSenderMethod
{
    public static void ConfigureServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<SmtpOptions>(configuration.GetSection("SmtpOptions"));
        services.Configure<RedirectConfiguration>(configuration.GetSection("Redirect"));

        services.AddSingleton(sp => sp.GetRequiredService<IOptions<RedirectConfiguration>>().Value);
    } 
}
