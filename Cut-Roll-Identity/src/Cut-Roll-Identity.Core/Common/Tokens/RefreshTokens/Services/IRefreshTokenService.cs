using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Models;

namespace Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Services;

public interface IRefreshTokenService
{
    public Task<int> DeleteRangeRefreshTokensAsync(string userId);
    Task<Guid> DeleteByIdAsync(Guid id);
    Task<Guid> CreateAsync(RefreshToken entity);
    Task<RefreshToken?> GetByIdAsync(Guid id);
}