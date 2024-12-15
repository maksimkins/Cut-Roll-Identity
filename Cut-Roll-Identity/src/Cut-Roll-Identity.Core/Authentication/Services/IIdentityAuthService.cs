using Cut_Roll_Identity.Core.Common.Tokens.AccessTokens.Entities;
using Cut_Roll_Identity.Core.Users.Models;
using Microsoft.AspNetCore.Identity;

namespace Cut_Roll_Identity.Core.Authentication.Services;

public interface IIdentityAuthService
{
    Task<string> RegisterAsync(User user, string password);

    Task<AccessToken> SignInAsync(string username, string password, bool rememberMe);
    
    Task<Guid> SignOutAsync(Guid refresh, string jwt);

    Task<AccessToken> UpdateToken(Guid refresh, string jwt);

    public Task SendConfirmationEmail(string email, string? confirmationLink);
    
    public Task<IdentityResult> ConfirmEmail(string userId, string token);
}