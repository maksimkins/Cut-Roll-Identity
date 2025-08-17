namespace Cut_Roll_Identity.Api.Common.Extensions.WebApplicationBuilder;

using Cut_Roll_Identity.Core.Common.Options;
using Microsoft.AspNetCore.Builder;

public static class ConfigureEmailSenderMethod
{
    public static void ConfigureEmailSender(this WebApplicationBuilder builder)
    {
        var smtpSection = builder.Configuration.GetSection("SmtpOptions");
        builder.Services.Configure<SmtpOptions>(smtpSection);
    } 
}
