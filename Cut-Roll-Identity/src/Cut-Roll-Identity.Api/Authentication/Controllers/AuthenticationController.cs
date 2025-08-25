using System.ComponentModel.DataAnnotations;
using System.Security.Authentication;
using Cut_Roll_Identity.Core.Authentication.Services;
using Cut_Roll_Identity.Core.Blob.Managers;
using Cut_Roll_Identity.Core.Users.Models;
using Cut_Roll_Identity.Infrastructure.Identities.Dtos;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Cut_Roll_Identity.Api.Common.Extensions.Controllers;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Cut_Roll_Identity.Api.Common.Configurations;
using Microsoft.Extensions.Options;

namespace Cut_Roll_Identity.Api.Authentication.Controllers;


[ApiController]
[Route("[controller]/[action]")]
public class AuthenticationController : ControllerBase
{
    private readonly IIdentityAuthService _identityAuthService;
    private readonly BaseBlobImageManager<string> _userImageManager;
    private readonly RedirectConfiguration _redirectConfig;
    public AuthenticationController(
        IIdentityAuthService identityAuthService,
        BaseBlobImageManager<string> userImageManager,
        IOptions<RedirectConfiguration> redirectConfig
    )
    {
        _redirectConfig = redirectConfig.Value;
        _identityAuthService = identityAuthService;
        _userImageManager = userImageManager;
    }

    [HttpPost]
    public async Task<IActionResult> LoginAsync([Required, FromBody] LoginDto loginDto)
    {
        try
        {
            var accessToken = await _identityAuthService.SignInAsync(loginDto.LoginIdentifier, loginDto.Password, true);
            return Ok(accessToken);
        }
        catch(InvalidCredentialException exeption)
        {
            return BadRequest(exeption.Message);
        }
        catch(ArgumentException exeption)
        {
            return BadRequest(exeption.Message);
        }
        catch(AuthenticationFailureException exeption)
        {
            return Unauthorized(new { message = exeption.Message });
        }
        catch (Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }


    [HttpPost]
    public async Task<IActionResult> RegistrationAsync([Required, FromBody] RegistrationDto registrationDto)
    {
        try
        {
            var user = new User
            {
                UserName = registrationDto.Name,
                Email = registrationDto.Email,
                AvatarPath = _userImageManager.GetDefaultImageUrl(),
            };

            await _identityAuthService.RegisterAsync(user, registrationDto.Password);
            var confirmationToken = await _identityAuthService.GenerateEmailConfirmationTokenAsync(user);

            var confirmationLink = $"https://cutnroll.it.com/emailConfirmed?userId={user.Id}&token={Uri.EscapeDataString(confirmationToken)}";
    
            await _identityAuthService.SendConfirmationEmail(user.Email, confirmationLink!);

            return Ok();
        }
        catch(ArgumentException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(InvalidCredentialException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }

    [HttpGet]
    public async Task<IActionResult> GoogleLoginCallback()
    {
        try
        {
            // Log the request for debugging
            var queryString = HttpContext.Request.QueryString.ToString();
            var headers = string.Join(", ", HttpContext.Request.Headers.Select(h => $"{h.Key}={h.Value}"));
            
            // Check if we have the authentication result
            Console.WriteLine("=== Google OAuth Callback Started ===");
            Console.WriteLine($"Query string: {queryString}");
            Console.WriteLine($"Headers: {headers}");
            Console.WriteLine($"Request Path: {HttpContext.Request.Path}");
            Console.WriteLine($"Request Scheme: {HttpContext.Request.Scheme}");
            Console.WriteLine($"Request Host: {HttpContext.Request.Host}");
            
            // Check if we have the authentication result
            Console.WriteLine("Attempting to authenticate with IdentityConstants.ExternalScheme...");
            var result = await HttpContext.AuthenticateAsync("Google");
            
            Console.WriteLine($"Authentication result - Succeeded: {result?.Succeeded}");
            Console.WriteLine($"Authentication result - Principal: {(result?.Principal != null ? "Present" : "Null")}");
            
            if (result != null && !result.Succeeded)
            {
                var failure = result?.Failure?.Message ?? "Unknown error";
                var failureType = result?.Failure?.GetType().Name ?? "Unknown";
                var failureStackTrace = result?.Failure?.StackTrace ?? "No stack trace";
                
                // Log the failure details
                Console.WriteLine($"Google OAuth failed: {failureType} - {failure}");
                Console.WriteLine($"Failure stack trace: {failureStackTrace}");
                Console.WriteLine($"Query string: {queryString}");
                Console.WriteLine($"Headers: {headers}");
                
                return Unauthorized($"Google auth failed: {failureType} - {failure}");
            }
            
            if (result?.Principal == null)
            {
                Console.WriteLine("Google OAuth succeeded but Principal is null");
                return Unauthorized("Google auth failed: Principal is null");
            }

            var email = result.Principal.FindFirstValue(ClaimTypes.Email);
            var name = result.Principal.FindFirstValue(ClaimTypes.Name);
            var externalId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(email))
            {
                Console.WriteLine("Google OAuth succeeded but email is null");
                return Unauthorized("Google auth failed: Email not provided");
            }

            var accessToken = await _identityAuthService.SignInWithExternalProviderAsync(email, name, externalId, null);
            var frontendUrl = $"{_redirectConfig.Scheme}://{_redirectConfig.Host}{_redirectConfig.Path}?jwt={accessToken.Jwt}&refresh={accessToken.Refresh}";

            return Redirect(frontendUrl);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception in GoogleLoginCallback: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
            return this.InternalServerError(ex.Message);
        }
    }


    [HttpGet]
    public IActionResult ExternalLogin()
    {
        try
        {
            var redirectUrl = Url.Action(nameof(GoogleLoginCallback), "Authentication");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, "Google");
        }
        catch (Exception ex)
        {
           return this.InternalServerError(ex.Message);
        }
    }


    [HttpGet]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        try
        {
            var result = await _identityAuthService.ConfirmEmail(userId, token);

            return result.Succeeded ? Ok() : BadRequest(error: result.Errors);
        }
        catch(ArgumentException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(InvalidCredentialException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }

    [Authorize]
    [HttpPatch]
    public async Task<IActionResult> LogoutAsync([Required, FromBody] Guid refresh)
    {
        try
        {
            var jwt = base.HttpContext.Request.Headers.Authorization.FirstOrDefault();
            var deletedToken = await _identityAuthService.SignOutAsync(refresh, jwt!);

            return Ok(new {
                Token = deletedToken
            });
        }
        catch(ArgumentException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(InvalidCredentialException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }
    
    [HttpGet]
    public IActionResult Error(string message)
    {
        return BadRequest(new { error = message ?? "Unknown OAuth error" });
    }

    [HttpGet]
    public IActionResult OAuthConfig()
    {
        try
        {
            var config = new
            {
                CallbackUrl = Url.Action(nameof(GoogleLoginCallback), "Authentication"),
                ExternalLoginUrl = Url.Action(nameof(ExternalLogin), "Authentication"),
                RequestScheme = HttpContext.Request.Scheme,
                RequestHost = HttpContext.Request.Host.ToString(),
                RequestPath = HttpContext.Request.Path.ToString(),
                FullCallbackUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}{Url.Action(nameof(GoogleLoginCallback), "Authentication")}",
                FullExternalLoginUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}{Url.Action(nameof(ExternalLogin), "Authentication")}"
            };
            
            return Ok(config);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpGet]
    public IActionResult TestOAuthConfig()
    {
        try
        {
            // Get the configuration from the service
            var configuration = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var googleOAuthSection = configuration.GetSection("OAuth:GoogleOAuth");
            
            var config = new
            {
                HasOAuthSection = googleOAuthSection.Exists(),
                ClientId = googleOAuthSection["ClientId"],
                HasClientSecret = !string.IsNullOrEmpty(googleOAuthSection["ClientSecret"]),
                CallbackPath = googleOAuthSection["CallbackPath"],
                EnvironmentVariables = new
                {
                    HasClientId = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GOOGLE_OAUTH_CLIENT_ID")),
                    HasClientSecret = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GOOGLE_OAUTH_CLIENT_SECRET")),
                    CallbackPath = Environment.GetEnvironmentVariable("GOOGLE_OAUTH_CALLBACK_PATH")
                }
            };
            
            return Ok(config);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpPut]
    public async Task<IActionResult> UpdateTokenAsync([Required, FromBody]Guid refresh)
    {
        try
        {
            var jwt = base.HttpContext.Request.Headers.Authorization.FirstOrDefault();
            var accessToken = await _identityAuthService.UpdateToken(refresh, jwt!);

            return Ok(accessToken);
        }
        catch(ArgumentException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(InvalidCredentialException exception)
        {
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }
}