namespace Cut_Roll_Identity.Api.Common.Extensions.WebApplication;

using Cut_Roll_Identity.Core.Authentication.Services;
using Cut_Roll_Identity.Core.Blob.Managers;
using Cut_Roll_Identity.Core.Users.Models;
using Microsoft.AspNetCore.Builder;

public static class SetupAdminMethod
{
    public async static Task SetupAdmin(this WebApplication app, IConfiguration configuration)
    {
        var adminUsername = configuration["DefaultAdmin:UserName"]!;
        var adminEmail = configuration["DefaultAdmin:Email"]!; 
        var adminPassword = configuration["DefaultAdmin:Password"]!;

        using (var scope = app.Services.CreateScope())
        {
            var identityAuthService = scope.ServiceProvider.GetRequiredService<IIdentityAuthService>();
            var blobImageManager = scope.ServiceProvider.GetRequiredService<BaseBlobImageManager<string>>();
            await identityAuthService.RegisterAsync(new User(){
                UserName = adminUsername,
                Email = adminEmail,
                EmailConfirmed = true,
                IsBanned = false,
                IsMuted = false,
                AvatarPath = blobImageManager.GetDefaultImageUrl(),
            }, adminPassword);
        }
    }
}
