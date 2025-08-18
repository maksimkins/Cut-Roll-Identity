using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Cut_Roll_Identity.Core.Blob.BlobOptions;
using Cut_Roll_Identity.Core.Blob.Managers;
using Cut_Roll_Identity.Core.Common.Services;
using Cut_Roll_Identity.Core.Users.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Cut_Roll_Identity.Infrastructure.Users.Managers;

public class UserImageManager : BaseBlobImageManager<string>
{
    private readonly IUserService _userService;
    IMessageBrokerService _messageBrokerService;
    private readonly string _defaultAvatarUrl;
    

    public UserImageManager(IUserService userService, BlobServiceClient blobServiceClient, 
        IMessageBrokerService messageBrokerService, IOptions<BlobOptions> blobOptions) 
        : base(blobServiceClient, blobOptions.Value.ContainerName, blobOptions.Value.Directory)
    {
        _userService = userService;
        _messageBrokerService = messageBrokerService;
        _defaultAvatarUrl = GetDefaultImageUrl();

    }


    public async override Task<string> DeleteImageAsync(string id)
    {
        var user = await _userService.GetUserByIdAsync(id) ?? throw new ArgumentException($"User with Id {id} not found.");

        if (!string.IsNullOrEmpty(user.AvatarPath) && !user.AvatarPath.Equals(_defaultAvatarUrl, StringComparison.OrdinalIgnoreCase))
        {
            var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
            var blobUri = new Uri(user.AvatarPath).AbsolutePath.TrimStart('/');
            var blobName = Path.GetFileName(blobUri);
            var blobClient = containerClient.GetBlobClient($"{_directory}/{blobName}");

            await blobClient.DeleteIfExistsAsync();
        }

        await _userService.PatchAvatarUrlPathAsync(id, _defaultAvatarUrl);

        await _messageBrokerService.PushAsync("user_update_avatar_admin", new
        {
            Id = user.Id,
            AvatarPath = _defaultAvatarUrl
        });

        await _messageBrokerService.PushAsync("user_update_avatar_news", new
        {
            Id = user.Id,
            AvatarPath = _defaultAvatarUrl
        });

        await _messageBrokerService.PushAsync("user_update_avatar_users", new
        {
            Id = user.Id,
            AvatarPath = _defaultAvatarUrl
        });

        return user.AvatarPath!;
    }

    public async override Task<string> SetImageAsync(string id, IFormFile? avatar)
    {
        var user = await _userService.GetUserByIdAsync(id) ?? throw new ArgumentException($"User with Id {id} not found.");

        if (avatar == null || avatar.Length == 0)
        {
            await _userService.PatchAvatarUrlPathAsync(id, _defaultAvatarUrl);
            return _defaultAvatarUrl;
        }

        var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
        await containerClient.CreateIfNotExistsAsync(PublicAccessType.Blob);

        var blobName = $"{user.Id}{Path.GetExtension(avatar.FileName)}";
        var blobClient = containerClient.GetBlobClient($"{_directory}/{blobName}");

        using (var stream = avatar.OpenReadStream())
        {
            await blobClient.UploadAsync(stream, new BlobHttpHeaders { ContentType = avatar.ContentType });
        }

        var avatarUrl = blobClient.Uri.ToString();
        await _userService.PatchAvatarUrlPathAsync(id, avatarUrl);

        await _messageBrokerService.PushAsync("user_update_avatar_admin", new
        {
            Id = user.Id,
            AvatarPath = avatarUrl
        });

        await _messageBrokerService.PushAsync("user_update_avatar_news", new
        {
            Id = user.Id,
            AvatarPath = avatarUrl
        });

        await _messageBrokerService.PushAsync("user_update_avatar_users", new
        {
            Id = user.Id,
            AvatarPath = avatarUrl
        });

        return avatarUrl;
    }
}