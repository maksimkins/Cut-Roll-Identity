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
    public async Task<IActionResult> ExternalLoginCallback()
    {
        try
        {
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);

             if (!result.Succeeded || result?.Principal == null)
                return Unauthorized("Google authentication failed");

            var email = result.Principal.FindFirstValue(ClaimTypes.Email);
            var name = result.Principal.FindFirstValue(ClaimTypes.Name);
            var externalId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
            //var pictureUrl = result.Principal.FindFirstValue("picture"); 
        
            var accessToken = await _identityAuthService.SignInWithExternalProviderAsync(email, name, externalId, null);

            var frontendUrl = $"{_redirectConfig.Scheme}://{_redirectConfig.Host}{_redirectConfig.Path}?jwt={accessToken.Jwt}&refresh={accessToken.Refresh}";

            return Redirect(frontendUrl);
        }
        catch (Exception ex)
        {
           return this.InternalServerError(ex.Message);
        }
    }


    [HttpGet]
    public IActionResult ExternalLogin()
    {
        try
        {
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Authentication");
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