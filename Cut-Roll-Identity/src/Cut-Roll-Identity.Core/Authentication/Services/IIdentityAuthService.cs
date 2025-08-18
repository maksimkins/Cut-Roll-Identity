using Cut_Roll_Identity.Core.Common.Tokens.AccessTokens.Entities;
using Cut_Roll_Identity.Core.Users.Models;
using Microsoft.AspNetCore.Identity;

namespace Cut_Roll_Identity.Core.Authentication.Services;

public interface IIdentityAuthService
{
    public Task RegisterAsync(User user, string password);
    public Task<AccessToken> SignInAsync(string username, string password, bool rememberMe);
    public Task<AccessToken> SignInWithExternalProviderAsync(string? email, string? name, string? externalId, string? pictureUrl);
    public Task<Guid> SignOutAsync(Guid refresh, string jwt);
    public Task<AccessToken> UpdateToken(Guid refresh, string jwt);
    public Task SendConfirmationEmail(string email, string? confirmationLink);
    public Task<IdentityResult> ConfirmEmail(string userId, string token);
    public Task<string> GenerateEmailConfirmationTokenAsync(User? user);
}