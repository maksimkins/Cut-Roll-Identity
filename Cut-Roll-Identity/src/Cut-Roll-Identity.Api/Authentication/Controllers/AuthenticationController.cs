using System.ComponentModel.DataAnnotations;
using System.Security.Authentication;
using Cut_Roll_Identity.Core.Authentication.Services;
using Cut_Roll_Identity.Core.Blob.Managers;
using Cut_Roll_Identity.Core.Users.Models;
using Cut_Roll_Identity.Infrastructure.Identities.Dtos;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Cut_Roll_Identity.Api.Authentication.Controllers;


[ApiController]
[Route("/api/[controller]/[action]")]
public class AuthenticationController : ControllerBase
{
    private readonly IIdentityAuthService _identityAuthService;
    private readonly BaseBlobImageManager<string> _userImageManager;

    public AuthenticationController(
        IIdentityAuthService identityAuthService,
        BaseBlobImageManager<string> userImageManager
    )
    {
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
            return Forbid(exeption.Message);
        }
        catch (Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }

    private IActionResult InternalServerError(string message)
    {
        throw new NotImplementedException();
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

            var result = await _identityAuthService.RegisterAsync(user, registrationDto.Password);

            return result.Succeeded ? Ok() : BadRequest(result.Errors);
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