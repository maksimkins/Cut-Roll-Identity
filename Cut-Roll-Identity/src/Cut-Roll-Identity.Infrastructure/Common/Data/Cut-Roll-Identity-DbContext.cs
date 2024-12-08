#pragma warning disable CS8618

using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Configurations;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Models;
using Cut_Roll_Identity.Core.Roles.Models;
using Cut_Roll_Identity.Core.Users.Configurations;
using Cut_Roll_Identity.Core.Users.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Cut_Roll_Identity.Infrastructure.Common.Data;

public class CutRollIdentityDbContext: IdentityDbContext<User, Role, string>
{
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    public CutRollIdentityDbContext(DbContextOptions options) : base(options)
    {}
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        modelBuilder.ApplyConfiguration(new UserConfiguration());
        modelBuilder.ApplyConfiguration(new RefreshTokenConfiguration());
    }

}
