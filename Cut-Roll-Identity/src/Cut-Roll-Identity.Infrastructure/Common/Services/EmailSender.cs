using System.Net;
using System.Net.Mail;
using Cut_Roll_Identity.Core.Common.Options;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;

namespace Cut_Roll_Identity.Infrastructure.Common.Services;

public class EmailSender : IEmailSender
{
    private readonly SmtpOptions _options;

    public EmailSender(IOptions<SmtpOptions> optionsSnapshot)
    {
        _options = optionsSnapshot.Value;
    }

    public async Task SendEmailAsync(string email, string subject, string message)
    {
        var smtpClient = new SmtpClient(_options.Server)
        {
            Port = int.Parse(_options.Port),
            Credentials = new NetworkCredential(_options.User, _options.Password),
            EnableSsl = true, 
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_options.Email, _options.Name), 
            Subject = subject, 
            Body = message,
            IsBodyHtml = true, 
        };

        mailMessage.To.Add(email); 

        await smtpClient.SendMailAsync(mailMessage); 
    }
}