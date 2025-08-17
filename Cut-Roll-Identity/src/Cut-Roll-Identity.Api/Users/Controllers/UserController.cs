namespace Cut_Roll_Identity.Api.Users.Controllers;

using System.Security.Claims;
using Cut_Roll_Identity.Api.Common.Extensions.Controllers;
using Cut_Roll_Identity.Core.Blob.Managers;
using Cut_Roll_Identity.Core.Users.Dtos;
using Cut_Roll_Identity.Core.Users.Models;
using Cut_Roll_Identity.Core.Users.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("[controller]/[action]")]
public class UserController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly BaseBlobImageManager<string> _userImageManager;

    public UserController(IUserService userService, BaseBlobImageManager<string> userImageManager)
    {
        _userService = userService;
        _userImageManager = userImageManager;
    }


    [HttpGet()]
    [Authorize]
    public async Task<IActionResult> GetUserRolesAsync()
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userService.GetUserByIdAsync(userId!);
            var roles = await _userService.GetRolesByUsernameAsync(user.UserName!);

            var userDto = new UserResponseDto()
            {
                User = user,
                Roles = roles
            };

            return Ok(userDto);
        }
        catch(ArgumentException exception)
        {   
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }


    [HttpPut("/api/[controller]")]
    [Authorize]
    public async Task<IActionResult> UpdateAsync([FromBody]UpdateUserDto updateUserDto)
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var result = await _userService.UpdateUserAsync(new User()
            {
                Id = userId!,
                Email = updateUserDto.Email,
                UserName = updateUserDto.UserName
            }, updateUserDto.Refresh);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            var jwt = HttpContext.Request.Headers.Authorization.FirstOrDefault();

            return Ok();
        }       
        catch(ArgumentException exception)
        {   
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }

    [HttpPatch("/api/[controller]/Avatar")]
    [Authorize]
    public async Task<IActionResult> UpdateAvatarAsync(IFormFile? avatar)
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var avatarUrlPath = await _userImageManager.SetImageAsync(userId!, avatar);

            return Ok(new {
                AvatarUrlPath = avatarUrlPath,
            });
        }       
        catch(ArgumentException exception)
        {   
            return BadRequest(exception.Message);
        }
        catch(InvalidOperationException exception)
        {   
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }

    [HttpGet("/api/[controller]/Avatar")]
    [Authorize]
    public async Task<IActionResult> GetAvatarAsync([FromQuery]string userId)
    {
        try
        {
            var user = await _userService.GetUserByIdAsync(userId);

            return Ok(new {
                AvatarUrlPath = user?.AvatarPath,
            });
        }       
        catch(ArgumentException exception)
        {   
            return BadRequest(exception.Message);
        }
        catch(InvalidOperationException exception)
        {   
            return BadRequest(exception.Message);
        }
        catch(Exception exception)
        {
            return this.InternalServerError(exception.Message);
        }
    }


}