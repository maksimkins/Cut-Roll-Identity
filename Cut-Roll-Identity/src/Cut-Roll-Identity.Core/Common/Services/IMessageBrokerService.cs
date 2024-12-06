namespace Cut_Roll_Identity.Core.Common.Services;

public interface IMessageBrokerService
{
    public Task PushAsync<T>(string destination, T obj);
}