using Cut_Roll_Identity.Core.Roles.Enums;

namespace Cut_Roll_Identity.Core.Roles.Services;

public interface IRoleService
{
    Task<string> GetRoleIdByName(UserRoles defaultRole);
    Task SetupRolesAsync();
}
