namespace Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Models;

public class RefreshToken
{
    public Guid Token { get; set; }
    public required string UserId { get; set; }
    public DateTime ExpirationDate { get; set; }
}
