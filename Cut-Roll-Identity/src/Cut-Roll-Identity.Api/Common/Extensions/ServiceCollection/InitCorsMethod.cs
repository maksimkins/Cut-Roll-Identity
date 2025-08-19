using Microsoft.AspNetCore.Cors.Infrastructure;

namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

public static class InitCorsMethod
{
    public static void InitCors(this IServiceCollection serviceCollection)
    {
        serviceCollection.AddCors(delegate (CorsOptions options)
        {
            options.AddPolicy("AllowAllOrigins", delegate (CorsPolicyBuilder builder)
            {
                builder
                    .AllowAnyOrigin()
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials(); 
            });
        });
    }
}