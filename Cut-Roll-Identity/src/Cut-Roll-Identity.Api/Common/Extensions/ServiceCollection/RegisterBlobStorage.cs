using Azure.Storage.Blobs;

namespace Cut_Roll_Identity.Api.Common.Extensions.ServiceCollection;

public static class RegisterBlobStorageMethod
{
    public static void RegisterBlobStorage(this IServiceCollection serviceCollection, IConfiguration configuration)
    {
        serviceCollection.AddSingleton(sp =>
        {
            var connectionString = configuration.GetConnectionString("AzureBlobStorage") 
                ?? throw new ArgumentNullException("connection string for blob storage is null");

            return new BlobServiceClient(connectionString);
        });
    }
}