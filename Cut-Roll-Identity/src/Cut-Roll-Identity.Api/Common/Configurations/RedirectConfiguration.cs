namespace Cut_Roll_Identity.Api.Common.Configurations;
public class RedirectConfiguration
{
    public string Scheme { get; set; } = "http"; 
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 443;
    public string Path { get; set; } = string.Empty;
}