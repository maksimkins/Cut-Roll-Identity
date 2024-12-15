using System.Security.Claims;
using Cut_Roll_Identity.Core.Common.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

public static class InitAuthMethod
{
    public static void InitAuth(this IServiceCollection serviceCollection, IConfiguration configuration)
    {
        var jwtSection = configuration.GetSection("Jwt") ?? throw new ArgumentNullException("cannot find section Jwt");
        serviceCollection.Configure<JwtOptions>(jwtSection);

        serviceCollection.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
        })
            .AddJwtBearer(options =>
            {
                var jwtOptions = jwtSection.Get<JwtOptions>() ?? throw new Exception("cannot find Jwt Section");

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtOptions.Issuer,

                    ValidateAudience = true,
                    ValidAudience = jwtOptions.Audience,

                    ValidateLifetime = true,

                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(jwtOptions!.KeyInBytes)
                };
            });

        serviceCollection.AddAuthorization(options => {

            options.AddPolicy(
                "Essentials",
                (policyBuilder) => {
                    policyBuilder.RequireAuthenticatedUser();
                    policyBuilder.RequireClaim("IsMuted");
                    policyBuilder.RequireClaim(ClaimTypes.Email);
                    policyBuilder.RequireClaim(ClaimTypes.Name);
                    policyBuilder.RequireClaim(ClaimTypes.NameIdentifier);
                }
            );
        });
    }
}

