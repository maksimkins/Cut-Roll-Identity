using Cut_Roll_Identity.Core.Common.Repositories.Base;
using Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Models;

namespace Cut_Roll_Identity.Core.Common.Tokens.RefreshTokens.Repositories;

public interface IRefreshTokenRepository : IDeleteByIdAsync<Guid, Guid>, ICreateAsync<RefreshToken, Guid>, IGetByIdAsync<RefreshToken, Guid>
{
    public Task<int> DeleteRangeRefreshTokensAsync(string userId);
}
