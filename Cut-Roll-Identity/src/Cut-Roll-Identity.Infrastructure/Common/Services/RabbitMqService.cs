
using System.Text;
using System.Text.Json;
using Cut_Roll_Identity.Core.Common.Options;
using Cut_Roll_Identity.Core.Common.Services;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;

namespace Cut_Roll_Identity.Infrastructure.Common.Services;

public class RabbitMqService : IMessageBrokerService
{
    private readonly ConnectionFactory rabbitMqConnectionFactory;

    public RabbitMqService(IOptions<RabbitMqOptions> optionsSnapshot)
    {
        this.rabbitMqConnectionFactory = new ConnectionFactory() {
            HostName = optionsSnapshot.Value.HostName,
            UserName = optionsSnapshot.Value.UserName,
            Password = optionsSnapshot.Value.Password,
        };
    }

    public Task PushAsync<T>(string destination, T obj)
    {
        using var connection = this.rabbitMqConnectionFactory.CreateConnection();
        using var channel = connection.CreateModel();

        var result = channel.QueueDeclare(
            queue: destination,
            durable: true,
            exclusive: false,
            autoDelete: false
        );

        var userJson = JsonSerializer.Serialize(obj);

        var messageInBytes = Encoding.UTF8.GetBytes(userJson);

        channel.BasicPublish(
            exchange: string.Empty,
            routingKey: destination,
            basicProperties: null,
            body: messageInBytes
        );

        return Task.CompletedTask;
    }
}