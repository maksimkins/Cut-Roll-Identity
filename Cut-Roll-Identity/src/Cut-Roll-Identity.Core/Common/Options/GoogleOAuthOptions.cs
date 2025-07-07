

namespace Cut_Roll_Identity.Core.Common.Options;

public class GoogleOAuthOptions
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public required string CallbackPath { get; set; }
}
