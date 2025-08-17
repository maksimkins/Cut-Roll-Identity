namespace Cut_Roll_Identity.Api.Common.Extensions.WebApplication;

using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using Cut_Roll_Identity.Infrastructure.Common.Data;

public static class UpdateDbAsyncMethod
{
    public async static Task UpdateDbAsync(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var services = scope.ServiceProvider;
            var dbContext = services.GetRequiredService<CutRollIdentityDbContext>();
        
            await dbContext.Database.MigrateAsync();
        }
    }
}
