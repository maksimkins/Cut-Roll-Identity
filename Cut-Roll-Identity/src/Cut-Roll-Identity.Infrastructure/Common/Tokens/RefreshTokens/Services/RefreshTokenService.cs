using Cut_Roll_Identity.Core.Common.Options;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Models;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Repositories;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Services;
using Microsoft.Extensions.Options;

namespace Cut_Roll_Identity.Infrastructure.Common.Tokens.RefreshTokens.Services;

public class RefreshTokenService : IRefreshTokenService
{
    private readonly IRefreshTokenRepository _repository;
    private readonly RefreshTokenOptions _refreshTokenOptions;
    public RefreshTokenService(IRefreshTokenRepository repository, IOptionsSnapshot<RefreshTokenOptions> refreshTokenOptionsSnapshot)
    {
        _repository = repository;
        _refreshTokenOptions = refreshTokenOptionsSnapshot.Value;
    }
    public async Task<Guid> CreateAsync(RefreshToken entity)
    {
        if(string.IsNullOrEmpty(entity.UserId) || string.IsNullOrWhiteSpace(entity.UserId))
        {
            throw new ArgumentException("cannot create RefreshToken due to userId is empty");
        }

        entity.ExpirationDate = DateTime.Now.AddMinutes(_refreshTokenOptions.LifeTimeInMinutes).ToUniversalTime();
        entity.Token = Guid.NewGuid();

        return await _repository.CreateAsync(entity);
    }

    public async Task<Guid> DeleteByIdAsync(Guid id)
    {
        await _repository.DeleteByIdAsync(id);
        return id;
    }

    public async Task<int> DeleteRangeRefreshTokensAsync(string userId)
    {
        if(string.IsNullOrEmpty(userId) || string.IsNullOrWhiteSpace(userId))
        {
            throw new ArgumentException("cannot create RefreshToken due to userId is empty");
        }

        var count = await _repository.DeleteRangeRefreshTokensAsync(userId);
        return count;
    }

    public async Task<RefreshToken?> GetByIdAsync(Guid id)
    {
        return await _repository.GetByIdAsync(id);
    }
}