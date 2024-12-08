using Cut_Roll_Identity.Core.Authentication.Services;

namespace Cut_Roll_Identity.Infrastructure.Common.Extensions.IdentityAuthServiceExtensions;

public static class IsValidEmailMethod
{
    public static bool IsValidEmail(this IIdentityAuthService authservice, string email)
    {
        var trimmedEmail = email.Trim();

        if (trimmedEmail.EndsWith(".")) {
            return false; 
        }
        try {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == trimmedEmail;
        }
        catch {
            return false;
        }
    }
}