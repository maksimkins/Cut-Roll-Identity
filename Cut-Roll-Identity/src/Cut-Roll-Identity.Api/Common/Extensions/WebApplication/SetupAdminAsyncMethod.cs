namespace Cut_Roll_Identity.Api.Common.Extensions.WebApplication;

using Cut_Roll_Identity.Core.Authentication.Services;
using Cut_Roll_Identity.Core.Blob.Managers;
using Cut_Roll_Identity.Core.Common.Services;
using Cut_Roll_Identity.Core.Roles.Enums;
using Cut_Roll_Identity.Core.Roles.Services;
using Cut_Roll_Identity.Core.Users.Models;
using Cut_Roll_Identity.Core.Users.Services;
using Microsoft.AspNetCore.Builder;

public static class SetupAdminAsyncMethod
{
    public async static Task SetupAdminAsync(this WebApplication app, IConfiguration configuration)
    {
        var adminUsername = configuration["DefaultAdmin:UserName"]!;
        var adminEmail = configuration["DefaultAdmin:Email"]!; 
        var adminPassword = configuration["DefaultAdmin:Password"]!;

        using (var scope = app.Services.CreateScope())
        {
            try
            {
                var userService = scope.ServiceProvider.GetRequiredService<IUserService>();
                var count = await userService.GetCountAsync();
                if (count == 0)
                {
                    var identityAuthService = scope.ServiceProvider.GetRequiredService<IIdentityAuthService>();
                    var blobImageManager = scope.ServiceProvider.GetRequiredService<BaseBlobImageManager<string>>();
                    var messageBrokerService = scope.ServiceProvider.GetRequiredService<IMessageBrokerService>();
                    var roleService = scope.ServiceProvider.GetRequiredService<IRoleService>();
                    var admin = new User()
                    {
                        UserName = adminUsername,
                        Email = adminEmail,
                        EmailConfirmed = true,
                        IsBanned = false,
                        IsMuted = false,
                        AvatarPath = blobImageManager.GetDefaultImageUrl(),
                    };
                    await userService.CreateUserAsync(admin, adminPassword);
                    var created = await userService.GetUserByEmailAsync(adminEmail);
                    await userService.AssignRoleToUserAsync(created.Id, UserRoles.Admin);

                    var defaultRole = UserRoles.Admin;
                    var defaultRoleId = await roleService.GetRoleIdByName(defaultRole);


                    await messageBrokerService.PushAsync("user_create_admin", new
                    {
                        UserName = created.UserName,
                        Id = created.Id,
                        RoleId = defaultRoleId,
                        Email = created.Email,
                        IsBanned = false,
                        IsMuted = false,
                        AvatarPath = created.AvatarPath
                    });

                    await messageBrokerService.PushAsync("user_create_news", new
                    {
                        UserName = created.UserName,
                        Id = created.Id,
                        Email = created.Email,
                        IsBanned = false,
                        IsMuted = false,
                        AvatarPath = created.AvatarPath
                    });

                    await messageBrokerService.PushAsync("user_create_users", new
                    {
                        UserName = created.UserName,
                        Id = created.Id,
                        Email = created.Email,
                        IsBanned = false,
                        IsMuted = false,
                        AvatarPath = created.AvatarPath
                    });
                }

            }
            catch(Exception exception)
            {
                Console.WriteLine(exception.Message);
            }
        }
    }
}
