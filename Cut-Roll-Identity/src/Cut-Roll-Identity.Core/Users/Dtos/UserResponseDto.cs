using Cut_Roll_Identity.Core.Users.Models;

namespace Cut_Roll_Identity.Core.Users.Dtos;

public class UserResponseDto
{
    public required User User { get; set; }
    public required ICollection<string> Roles { get; set; }
}