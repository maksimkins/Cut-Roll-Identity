using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Http;

namespace Cut_Roll_Identity.Core.Blob.Managers;

public abstract class BaseBlobImageManager<TId>
{
    protected readonly BlobServiceClient _blobServiceClient;
    protected readonly string _containerName;

    protected BaseBlobImageManager(BlobServiceClient blobServiceClient, string containerName)
    {
        _blobServiceClient = blobServiceClient;
        _containerName = containerName;
    }

    public string GetDefaultImageUrl()
    {
        // var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
        // var defaultImageBlobName = "default-image.png";

        // var blobClient = containerClient.GetBlobClient(defaultImageBlobName);
        
        // if (!blobClient.Exists())
        //     throw new InvalidOperationException("Default image does not exist in Blob Storage.");

        return "";//blobClient.Uri.ToString();
    }

    public abstract Task<string> DeleteImageAsync(TId id);
	public abstract Task<string> SetImageAsync(TId id, IFormFile? logo);
}