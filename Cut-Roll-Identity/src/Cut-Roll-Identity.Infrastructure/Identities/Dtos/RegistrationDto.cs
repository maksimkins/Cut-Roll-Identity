namespace Cut_Roll_Identity.Infrastructure.Identities.Dtos;

public class RegistrationDto
{
    public required string Name { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
}
