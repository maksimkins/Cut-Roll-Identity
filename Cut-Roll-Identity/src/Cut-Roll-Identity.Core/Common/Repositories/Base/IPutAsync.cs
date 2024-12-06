namespace Cut_Roll_Identity.Core.Common.Repositories.Base;
public interface IPutAsync<TEntity, TReturn> 
{
    Task<TReturn> PutAsync(TEntity entity);
}