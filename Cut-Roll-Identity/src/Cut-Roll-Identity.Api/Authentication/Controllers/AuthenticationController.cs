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
using System.Text.Json;

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

            var confirmationLink = Url.Action(
                "ConfirmEmail",
                "Authentication",
                new { userId = user.Id, token = confirmationToken },
                protocol: HttpContext.Request.Scheme
            );
    
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
    public IActionResult ExternalLogin()
    {
        try
        {
            // Get the configured callback path
            var configuration = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var callbackPath = configuration["OAuth:GoogleOAuth:CallbackPath"];
            
            if (string.IsNullOrEmpty(callbackPath))
            {
                return BadRequest("OAuth callback path not configured");
            }

            // Build the full callback URL
            var fullCallbackUrl = $"https://cutnroll.it.com{callbackPath}";
            var properties = new AuthenticationProperties { RedirectUri = fullCallbackUrl };
            
            Console.WriteLine($"ExternalLogin - Redirecting to Google with callback: {fullCallbackUrl}");
            
            return Challenge(properties, "Google");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ExternalLogin Error: {ex.Message}");
            return this.InternalServerError(ex.Message);
        }
    }

    [HttpGet]
    public async Task<IActionResult> GoogleLoginCallback(string code, string state)
    {
        try
        {
            var googleOAuthSection = HttpContext.RequestServices.GetRequiredService<IConfiguration>().GetSection("OAuth:GoogleOAuth");
            var clientId = googleOAuthSection["ClientId"];
            var clientSecret = googleOAuthSection["ClientSecret"];
            var redirectUri = $"https://cutnroll.it.com{googleOAuthSection["CallbackPath"]}";
    
            // 1️⃣ Exchange code for tokens
            using var httpClient = new HttpClient();
            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "https://oauth2.googleapis.com/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "code", code },
                    { "client_id", clientId ?? throw new ArgumentNullException("ClientId is not configured") },
                    { "client_secret", clientSecret  ?? throw new ArgumentNullException("ClientSecret is not configured") },
                    { "redirect_uri", redirectUri ?? throw new ArgumentNullException("RedirectUri is not configured") },
                    { "grant_type", "authorization_code" }
                })
            };
    
            var tokenResponse = await httpClient.SendAsync(tokenRequest);
            tokenResponse.EnsureSuccessStatusCode();
            var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(tokenJson)!;
    
            var accessToken = tokenData["access_token"].GetString();
            if (string.IsNullOrEmpty(accessToken))
                return Unauthorized("Failed to obtain Google access token");
    
            // 2️⃣ Get user info from Google
            var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "https://www.googleapis.com/oauth2/v2/userinfo");
            userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
    
            var userInfoResponse = await httpClient.SendAsync(userInfoRequest);
            userInfoResponse.EnsureSuccessStatusCode();
            var userInfoJson = await userInfoResponse.Content.ReadAsStringAsync();
            var userInfo = JsonSerializer.Deserialize<Dictionary<string, string>>(userInfoJson)!;
    
            var email = userInfo.GetValueOrDefault("email");
            var name = userInfo.GetValueOrDefault("name");
            var externalId = userInfo.GetValueOrDefault("id");
    
            if (string.IsNullOrEmpty(email))
                return Unauthorized("Google did not return an email");
    
    
        
    
            // Sign in the user
            var accessTokenMy = await _identityAuthService.SignInWithExternalProviderAsync(
                email, name, externalId, null
            );
            
            // Build redirect URL
            var frontendUrl = $"{_redirectConfig.Scheme}://{_redirectConfig.Host}{_redirectConfig.Path}?jwt={accessTokenMy.Jwt}&refresh={accessTokenMy.Refresh}";
            
            Console.WriteLine($"Redirecting to frontend: {frontendUrl}");

            return Redirect(frontendUrl);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"GoogleLoginCallback Exception: {ex.Message}");
            Console.WriteLine($"Stack Trace: {ex.StackTrace}");
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

    [HttpGet]
    public IActionResult Error(string message)
    {
        Console.WriteLine($"OAuth Error: {message}");
        return BadRequest(new { error = message ?? "Unknown OAuth error" });
    }

    [HttpGet]
    public IActionResult OAuthStatus()
    {
        try
        {
            var configuration = HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var callbackPath = configuration["OAuth:GoogleOAuth:CallbackPath"];
            var clientId = configuration["OAuth:GoogleOAuth:ClientId"];
            var hasClientSecret = !string.IsNullOrEmpty(configuration["OAuth:GoogleOAuth:ClientSecret"]);

            var status = new
            {
                OAuthConfigured = !string.IsNullOrEmpty(clientId) && hasClientSecret && !string.IsNullOrEmpty(callbackPath),
                ClientId = clientId,
                HasClientSecret = hasClientSecret,
                CallbackPath = callbackPath,
                FullCallbackUrl = !string.IsNullOrEmpty(callbackPath) ? $"https://cutnroll.it.com{callbackPath}" : null,
                RequestInfo = new
                {
                    Scheme = HttpContext.Request.Scheme,
                    Host = HttpContext.Request.Host.ToString(),
                    Path = HttpContext.Request.Path.ToString()
                }
            };

            return Ok(status);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}