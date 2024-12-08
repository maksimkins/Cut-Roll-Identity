#pragma warning disable CS1998

using Cut_Roll_Identity.Core.Common.Services;
using Cut_Roll_Identity.Core.Roles.Enums;
using Cut_Roll_Identity.Core.Roles.Models;
using Cut_Roll_Identity.Core.Roles.Services;
using Microsoft.AspNetCore.Identity;

namespace Cut_Roll_Identity.Infrastructure.Roles.Services;


public class RoleService : IRoleService
{
    private readonly RoleManager<Role> _roleManager;

    public RoleService(RoleManager<Role> roleManager)
    {
        _roleManager = roleManager;
    }

    public async Task<string> GetRoleIdByName(UserRoles roleName)
    {
        return _roleManager.Roles.Where(r => r.Name == roleName.ToString()).FirstOrDefault()!.Id ?? throw new Exception($"role {roleName} doen't exists");
    }
    public async Task SetupRolesAsync()
    {
        List<string> roleNames = [$"{UserRoles.Admin}", $"{UserRoles.User}",];
        // List<string> ids = ["57082502-2ccf-4610-b865-fdd780b8bf1d", "6424977e-131b-4f9f-aa3f-9626dd293021", "c0d1b7c6-a250-4a02-a0c8-a8896de8140e"];
        
        

        for (int i = 0; i < roleNames.Count; i++)
        {
            var roleExists = await this._roleManager.RoleExistsAsync(roleNames[i]);

            if (!roleExists)
            {
                var role = new Role()
                {
                    // Id = ids[i],
                    Name = roleNames[i]
                };
                var result = await this._roleManager.CreateAsync(role);
                
                if (!result.Succeeded)
                    throw new Exception("cannot create roles!!");
        
            }
        }
    }
}

