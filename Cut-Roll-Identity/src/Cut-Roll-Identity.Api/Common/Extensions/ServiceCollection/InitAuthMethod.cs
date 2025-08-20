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
                
                // Force HTTPS for all OAuth operations
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
                options.CorrelationCookie.SameSite = SameSiteMode.None;
                options.CorrelationCookie.HttpOnly = true;
                
                // Set explicit redirect URI to force HTTPS
                var redirectUri = $"https://cutnroll.it.com{googleOAuthOptions.CallbackPath}";
                Console.WriteLine($"OAuth Configuration - Redirect URI: {redirectUri}");
                
                // Force HTTPS for OAuth
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
                options.CorrelationCookie.SameSite = SameSiteMode.None;
                
                // Configure events for debugging
                options.Events = new Microsoft.AspNetCore.Authentication.OAuth.OAuthEvents
                {
                    OnRemoteFailure = context =>
                    {
                        context.HandleResponse();
                        var errorMessage = context?.Failure?.Message ?? "Unknown OAuth error";
                        var innerException = context?.Failure?.InnerException?.Message ?? "No inner exception";
                        var failureType = context?.Failure?.GetType().Name ?? "Unknown";
                        var stackTrace = context?.Failure?.StackTrace ?? "No stack trace";
                        
                        Console.WriteLine($"OAuth Remote Failure: {failureType} - {errorMessage}");
                        Console.WriteLine($"OAuth Remote Failure Inner: {innerException}");
                        Console.WriteLine($"OAuth Remote Failure Stack: {stackTrace}");
                        
                        context?.Response.Redirect($"/Authentication/Error?message={Uri.EscapeDataString(errorMessage)}");
                        return Task.CompletedTask;
                    },
                    OnTicketReceived = context =>
                    {
                        Console.WriteLine("OAuth Ticket Received Successfully");
                        return Task.CompletedTask;
                    },
                    OnCreatingTicket = context =>
                    {
                        Console.WriteLine("OAuth Creating Ticket");
                        return Task.CompletedTask;
                    },
                    OnRedirectToAuthorizationEndpoint = context =>
                    {
                        Console.WriteLine($"OAuth Redirect to: {context.RedirectUri}");
                        context.Response.Redirect(context.RedirectUri);
                        return Task.CompletedTask;
                    },
                    OnAccessDenied = context =>
                    {
                        Console.WriteLine($"OAuth Access Denied: {context.AccessDeniedPath}");
                        return Task.CompletedTask;
                    },
                    OnRemoteError = context =>
                    {
                        Console.WriteLine($"OAuth Remote Error: {context?.Failure?.Message}");
                        return Task.CompletedTask;
                    }
                };
            });

        serviceCollection.AddAuthorization(options => {

            options.AddPolicy(
                "Essentials",
                (policyBuilder) => {
                    policyBuilder.RequireAuthenticatedUser();
                    policyBuilder.RequireClaim("IsMuted");
                    policyBuilder.RequireClaim("EmailConfirmed");
                    policyBuilder.RequireClaim(ClaimTypes.Email);
                    policyBuilder.RequireClaim(ClaimTypes.Name);
                    policyBuilder.RequireClaim(ClaimTypes.NameIdentifier);
                }
            );
        });
    }
}

