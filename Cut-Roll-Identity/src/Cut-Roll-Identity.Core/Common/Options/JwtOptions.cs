using System.Text;

namespace Cut_Roll_Identity.Core.Common.Options;

public class JwtOptions
{
    public required string Key { get; set; }
    public byte[] KeyInBytes => Encoding.ASCII.GetBytes(Key);
    public int LifeTimeInMinutes { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
}