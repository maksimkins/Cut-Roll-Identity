using Microsoft.Extensions.Configuration;

namespace Cut_Roll_Identity.Infrastructure.Common.Extensions;

public static class ConfigurationExtensions
{
    public static string GetConnectionStringOfThrowArgumentException(this IConfiguration configuration, string path)
    {
        var connectionString = configuration.GetConnectionString(path);

        if (string.IsNullOrEmpty(connectionString))
        {
            throw new ArgumentException($"Connection string not found in settings file by path: '{path}'", connectionString);
        }

        return connectionString;
    }
}