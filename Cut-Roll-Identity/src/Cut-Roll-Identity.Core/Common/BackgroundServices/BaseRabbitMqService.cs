using System.Text;
using Cut_Roll_Identity.Core.Common.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Cut_Roll_Identity.Core.Common.BackgroundServices;

public abstract class BaseRabbitMqService
{
    private readonly ConnectionFactory rabbitMqConnectionFactory;

    protected readonly IServiceScopeFactory serviceScopeFactory;

    private static readonly List<(IConnection connection, IModel model)> connections = new();

    public BaseRabbitMqService(IOptions<RabbitMqOptions> optionsSnapshot, IServiceScopeFactory serviceScopeFactory)
    {
        this.rabbitMqConnectionFactory = new ConnectionFactory()
        {
            HostName = optionsSnapshot.Value.HostName,
            UserName = optionsSnapshot.Value.UserName,
            Password = optionsSnapshot.Value.Password
        };

        this.serviceScopeFactory = serviceScopeFactory;
    }

    protected void StartListening(string queueName, Action<string> eventHandler)
    {
        var connection = rabbitMqConnectionFactory.CreateConnection();
        var model = connection.CreateModel();

        model.QueueDeclare(
            queue: queueName,
            durable: true,
            exclusive: false,
            autoDelete: false
        );

        var consumer = new EventingBasicConsumer(model);

        consumer.Received += (sender, deliverEventArgs) =>
        {
            string message = Encoding.ASCII.GetString(deliverEventArgs.Body.ToArray());
            eventHandler(message);
        };

        model.BasicConsume(
            queue: queueName,
            autoAck: true,
            consumer: consumer
        );

        connections.Add((connection, model));
    }
}