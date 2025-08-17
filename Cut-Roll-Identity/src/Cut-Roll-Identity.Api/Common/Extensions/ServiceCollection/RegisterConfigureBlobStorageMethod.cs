using Azure.Storage.Blobs;
using Cut_Roll_Identity.Core.Blob.BlobOptions;

namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

public static class RegisterConfigureBlobStorageMethod
{
    public static void RegisterConfigureBlobStorage(this IServiceCollection serviceCollection, IConfiguration configuration)
    {
        serviceCollection.AddSingleton(sp =>
        {
            var connectionString = configuration.GetConnectionString("AzureBlobStorage")
                ?? throw new ArgumentNullException("connection string for blob storage is null");

            return new BlobServiceClient(connectionString);
        });
        
        serviceCollection.Configure<BlobOptions>(configuration.GetSection("BlobStorage"));
    }
}