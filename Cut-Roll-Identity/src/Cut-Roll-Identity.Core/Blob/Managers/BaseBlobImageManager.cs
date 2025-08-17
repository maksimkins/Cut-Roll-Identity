using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Http;

namespace Cut_Roll_Identity.Core.Blob.Managers;

public abstract class BaseBlobImageManager<TId>
{
    protected readonly BlobServiceClient _blobServiceClient;
    protected readonly string _containerName;
    protected readonly string _directory;

    protected BaseBlobImageManager(BlobServiceClient blobServiceClient, string containerName, string directory)
    {
        _blobServiceClient = blobServiceClient;
        _containerName = containerName;
        _directory = directory;
    }

    public string GetDefaultImageUrl()
    {
        var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
        var defaultImageBlobName = "default.jpg";

        var blobClient = containerClient.GetBlobClient($"{_directory}/{defaultImageBlobName}");
        
        if (!blobClient.Exists())
            throw new InvalidOperationException("Default image does not exist in Blob Storage.");

        return blobClient.Uri.ToString();
    }

    public abstract Task<string> DeleteImageAsync(TId id);
	public abstract Task<string> SetImageAsync(TId id, IFormFile? logo);
}