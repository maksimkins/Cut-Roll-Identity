using System.Security.Claims;
using Cut_Roll_Identity.Core.Common.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

public static class InitAuthMethod
{
    public static void InitAuth(this IServiceCollection serviceCollection, IConfiguration configuration)
    {
        var jwtSection = configuration.GetSection("Jwt") ?? throw new ArgumentNullException("cannot find section Jwt");
        var googleOAuthSection = configuration.GetSection("OAuth:GoogleOAuth") ?? throw new ArgumentNullException("cannot find section GoogleOAuth");

        serviceCollection.Configure<JwtOptions>(jwtSection);
        serviceCollection.Configure<GoogleOAuthOptions>(googleOAuthSection);

        serviceCollection.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = IdentityConstants.ExternalScheme;

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
            })
            .AddGoogle("Google", options =>
            {
                var googleOAuthOptions = googleOAuthSection.Get<GoogleOAuthOptions>() ?? throw new Exception("cannot find GoogleOAuth Section");

                options.ClientId = googleOAuthOptions.ClientId;
                options.ClientSecret = googleOAuthOptions.ClientSecret;
                options.CallbackPath = googleOAuthOptions.CallbackPath; 

                options.Scope.Add("profile");
                options.Scope.Add("email");

                options.SaveTokens = true; 
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

