namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

using Cut_Roll_Identity.Core.Common.Options;

public static class ConfigureEmailSenderMethod
{
    public static void ConfigureEmailSender(this IServiceCollection services, IConfiguration configuration)
    {   
        services.Configure<SmtpOptions>(configuration.GetSection("SmtpOptions"));
    } 
}
