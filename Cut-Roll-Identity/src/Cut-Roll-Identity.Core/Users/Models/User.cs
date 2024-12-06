#pragma warning disable CS8618

using System.ComponentModel;
using System.Text.Json.Serialization;
using Cut_Roll_Identity.Core.Common.Models.Base;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Models;
using Microsoft.AspNetCore.Identity;

namespace Cut_Roll_Identity.Core.Users.Models;

public class User : IdentityUser, IBanable, IMuteable
{
    [DefaultValue(false)]
    public bool IsBanned { get; set; }

    [DefaultValue(false)]
    public bool IsMuted { get; set; }
    public string? AvatarPath { get; set; }
    [JsonIgnore]
    public ICollection<RefreshToken> RefreshTokens { get; set; }

}