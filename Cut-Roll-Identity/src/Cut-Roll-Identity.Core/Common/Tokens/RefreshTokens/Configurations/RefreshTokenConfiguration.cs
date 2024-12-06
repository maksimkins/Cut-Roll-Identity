using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder
            .HasKey(rt => rt.Token);
        
        builder
            .Property(f => f.ExpirationDate)
            .IsRequired();
    }
}