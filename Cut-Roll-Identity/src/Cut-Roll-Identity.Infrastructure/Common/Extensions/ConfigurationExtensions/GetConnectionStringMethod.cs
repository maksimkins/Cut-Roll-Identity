using Microsoft.Extensions.Configuration;

namespace Cut_Roll_Identity.Infrastructure.Common.ConfigurationExtensions.Extensions;

public static class GetConnectionStringMethod
{
    public static string GetConnectionStringOrThrowArgumentException(this IConfiguration configuration, string path)
    {
        var connectionString = configuration.GetConnectionString(path);

        if (string.IsNullOrEmpty(connectionString))
        {
            throw new ArgumentException($"Connection string not found in settings file by path: '{path}'", connectionString);
        }

        return connectionString;
    }
}