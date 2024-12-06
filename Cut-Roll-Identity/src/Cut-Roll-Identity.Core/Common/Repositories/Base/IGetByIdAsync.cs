namespace Cut_Roll_Identity.Core.Common.Repositories.Base;

public interface IGetByIdAsync<TEntity, TId>
{
    Task<TEntity?> GetByIdAsync(TId id);
}