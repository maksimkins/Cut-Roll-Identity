namespace Cut_Roll_Identity.Api.Common.Extensions.WebApplicationBuilder;

using System;
using Microsoft.AspNetCore.Builder;

public static class SetupVariablesMethod
{
    public static void SetupVariables(this WebApplicationBuilder builder)
    {
        var postgresConnectionString = Environment.GetEnvironmentVariable("POSTGRES_CONNECTION_STRING") ?? throw new SystemException("there is no var POSTGRES_CONNECTION_STRING");
        var azureConnectionString = Environment.GetEnvironmentVariable("BLOB_STORAGE_CONNECTION_STRING") ?? throw new SystemException("there is no var BLOB_STORAGE_CONNECTION_STRING");
        
        var jwt_key = Environment.GetEnvironmentVariable("JWT_KEY") ?? throw new SystemException("there is no var JWT_KEY");
        var jwt_life_time = Environment.GetEnvironmentVariable("JWT_LIFE_TIME_IN_MINUTES") ?? throw new SystemException("there is no var JWT_LIFE_TIME_IN_MINUTES");
        var jwt_issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new SystemException("there is no var JWT_ISSUER");
        var jwt_audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new SystemException("there is no var JWT_AUDIENCE");

        var rabbit_mq_hostname = Environment.GetEnvironmentVariable("RABBIT_MQ_HOSTNAME") ?? throw new SystemException("there is no var RABBIT_MQ_HOSTNAME");
        var rabbit_mq_username = Environment.GetEnvironmentVariable("RABBIT_MQ_USERNAME") ?? throw new SystemException("there is no var RABBIT_MQ_USERNAME");
        var rabbit_mq_password = Environment.GetEnvironmentVariable("RABBIT_MQ_PASSWORD") ?? throw new SystemException("there is no var RABBIT_MQ_PASSWORD");

        var default_admin_username = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_USERNAME") ?? throw new SystemException("there is no var DEFAULT_ADMIN_USERNAME");
        var default_admin_email = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_EMAIL") ?? throw new SystemException("there is no var DEFAULT_ADMIN_EMAIL");
        var default_admin_password = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_PASSWORD") ?? throw new SystemException("there is no var DEFAULT_ADMIN_PASSWORD");
        

        var email_port = Environment.GetEnvironmentVariable("EMAIL_PORT") ?? throw new SystemException("there is no var EMAIL_PORT");
        var email_server = Environment.GetEnvironmentVariable("EMAIL_SERVER") ?? throw new SystemException("there is no var EMAIL_SERVER");
        var email_user = Environment.GetEnvironmentVariable("EMAIL_USER") ?? throw new SystemException("there is no var EMAIL_USER");
        var email_email = Environment.GetEnvironmentVariable("EMAIL_EMAIL") ?? throw new SystemException("there is no var EMAIL_EMAIL");
        var email_name = Environment.GetEnvironmentVariable("EMAIL_NAME") ?? throw new SystemException("there is no var EMAIL_NAME");
        var email_password = Environment.GetEnvironmentVariable("EMAIL_PASSWORD") ?? throw new SystemException("there is no var EMAIL_PASSWORD");
        


        builder.Configuration["Jwt:Key"] = jwt_key;
        builder.Configuration["Jwt:LifeTimeInMinutes"] =  jwt_life_time;
        builder.Configuration["Jwt:Issuer"] = jwt_issuer;
        builder.Configuration["Jwt:Audience"] = jwt_audience;

        builder.Configuration["ConnectionStrings:SqlConnection"] = postgresConnectionString;
        builder.Configuration["ConnectionStrings:AzureBlobStorage"] = azureConnectionString;

        builder.Configuration["RabbitMq:HostName"] = rabbit_mq_hostname;
        builder.Configuration["RabbitMq:UserName"] = rabbit_mq_username;
        builder.Configuration["RabbitMq:Password"] = rabbit_mq_password;

        builder.Configuration["DefaultAdmin:UserName"] = default_admin_username;
        builder.Configuration["DefaultAdmin:Email"] = default_admin_email;
        builder.Configuration["DefaultAdmin:Password"] = default_admin_password;

        builder.Configuration["SmtpOptions:Port"] = email_port;
        builder.Configuration["SmtpOptions:Server"] = email_server;
        builder.Configuration["SmtpOptions:User"] = email_user;
        builder.Configuration["SmtpOptions:Email"] = email_email;
        builder.Configuration["SmtpOptions:Name"] = email_name;
        builder.Configuration["SmtpOptions:Password"] = email_password;
        
    }
}