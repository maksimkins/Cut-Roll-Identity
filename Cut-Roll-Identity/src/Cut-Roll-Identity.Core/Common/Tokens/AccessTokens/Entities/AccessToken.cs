namespace Cut_Roll_Identity.Core.Common.Tokens.AccessTokens.Entities;

public class AccessToken
{
    public Guid Refresh { get; set; }
    public required string Jwt { get; set; }
}
