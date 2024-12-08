namespace Cut_Roll_Identity.Infrastructure.Identities.Dtos;

public class LoginDto
{
    public required string LoginIdentifier { get; set; }
    public required string Password { get; set; }
}