namespace Cut_Roll_Identity.Infrastructure.Common.Dtos;

public class UpdateMuteUserDto
{
    public required string Id { get; set; }
    public required bool IsMuted { get; set; }
}
