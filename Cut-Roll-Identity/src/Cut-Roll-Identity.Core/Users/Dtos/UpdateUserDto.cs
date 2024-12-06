namespace Cut_Roll_Identity.Core.Users.Dtos;

public class UpdateUserDto
{
    public string? UserName { get; set; }
    public string? Email { get; set; }
    public Guid Refresh { get; set; }
}