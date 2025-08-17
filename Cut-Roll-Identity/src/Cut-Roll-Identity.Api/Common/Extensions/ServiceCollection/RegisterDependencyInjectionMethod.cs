using Cut_Roll_Identity.Core.Authentication.Services;
using Cut_Roll_Identity.Core.Blob.Managers;
using Cut_Roll_Identity.Core.Common.Services;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Repositories;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Services;
using Cut_Roll_Identity.Core.Roles.Services;
using Cut_Roll_Identity.Core.Users.Services;
using Cut_Roll_Identity.Infrastructure.Authentication.Services;
using Cut_Roll_Identity.Infrastructure.Common.Services;
using Cut_Roll_Identity.Infrastructure.Common.Tokens.RefreshTokens.Repositories.Ef_Core;
using Cut_Roll_Identity.Infrastructure.Common.Tokens.RefreshTokens.Services;
using Cut_Roll_Identity.Infrastructure.Roles.BackgroundServices;
using Cut_Roll_Identity.Infrastructure.Roles.Services;
using Cut_Roll_Identity.Infrastructure.Users.BackgroundServices;
using Cut_Roll_Identity.Infrastructure.Users.Managers;
using Cut_Roll_Identity.Infrastructure.Users.Services;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

public static class RegisterDependencyInjectionMethod 
{
    public static void RegisterDependencyInjection(this IServiceCollection serviceCollection)
    {
        serviceCollection.AddTransient<IUserService, UserService>();
        serviceCollection.AddTransient<IRoleService, RoleService>();
        serviceCollection.AddTransient<IIdentityAuthService, IdentityAuthService>();

        serviceCollection.AddTransient<IRefreshTokenRepository, RefreshTokenEfCoreRepository>();
        serviceCollection.AddTransient<IRefreshTokenService, RefreshTokenService>();

        serviceCollection.AddTransient<BaseBlobImageManager<string>, UserImageManager>();
        
        serviceCollection.AddTransient<IMessageBrokerService, RabbitMqService>();
        serviceCollection.AddSingleton<IEmailSender, EmailSender>();
        
        serviceCollection.AddHostedService<UserRabbitMqService>();
        serviceCollection.AddHostedService<RoleRabbitMqService>();
    } 
}