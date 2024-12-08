using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Cut_Roll_Identity.Core.Common.BackgroundServices;
using Cut_Roll_Identity.Core.Common.Options;
using Cut_Roll_Identity.Core.Users.Services;
using Cut_Roll_Identity.Infrastructure.Common.Dtos;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Cut_Roll_Identity.Infrastructure.Common.BackgroundServices;

public class RoleRabbitMqService: BaseRabbitMqService, IHostedService
{
    public RoleRabbitMqService(IOptions<RabbitMqOptions> optionsSnapshot, IServiceScopeFactory serviceScopeFactory) :
        base(optionsSnapshot, serviceScopeFactory)
    {
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        base.StartListening("role_update_identity", async message => {
            using (var scope = base.serviceScopeFactory.CreateScope())
            {
                var userService = scope.ServiceProvider.GetRequiredService<IUserService>();

                var dto = JsonSerializer.Deserialize<UpdateUserRoleDto>(message)!;

                await userService.UpdateUserRoleAsync(userId: dto.Id, roleId: dto.RoleId);
            }
        });



        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}