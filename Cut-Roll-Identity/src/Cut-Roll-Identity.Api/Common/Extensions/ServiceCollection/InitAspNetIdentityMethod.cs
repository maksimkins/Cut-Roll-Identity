using Cut_Roll_Identity.Core.Roles.Models;
using Cut_Roll_Identity.Core.Users.Models;
using Cut_Roll_Identity.Infrastructure.Common.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

public static class InitAspNetIdentityMethod
{
    public static void InitAspnetIdentity(this IServiceCollection serviceCollection, IConfiguration configuration)
    {
        serviceCollection.AddDbContext<CutRollIdentityDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("SqlConnection") ?? throw new SystemException("connectionString is not set");
            options.UseNpgsql(connectionString);
        });

        serviceCollection.AddIdentity<User, Role>( (options) => {
            options.User.RequireUniqueEmail = true;
        })
            .AddEntityFrameworkStores<CutRollIdentityDbContext>()
            .AddDefaultTokenProviders()
            .AddSignInManager();
    }
}