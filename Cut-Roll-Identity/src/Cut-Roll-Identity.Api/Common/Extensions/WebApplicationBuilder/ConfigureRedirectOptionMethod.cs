namespace Cut_Roll_Identity.Api.Common.Extensions.WebApplicationBuilder;

using Cut_Roll_Identity.Api.Common.Configurations;
using Microsoft.AspNetCore.Builder;

public static class ConfigureRedirectOptionMethod
{
    public static void ConfigureRedirectOption(this WebApplicationBuilder builder)
    {
        var redirectSection = builder.Configuration.GetSection("Redirect");
        builder.Services.Configure<RedirectConfiguration>(redirectSection);
    }

}
