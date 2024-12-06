namespace Cut_Roll_Identity.Core.Common.Repositories.Base;

public interface ICreateAsync<TEntity, TReturn> 
{
    Task<TReturn> CreateAsync(TEntity entity);
}