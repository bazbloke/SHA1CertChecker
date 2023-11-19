using SHA1CertChecker.Function;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Reflection;

[assembly: FunctionsStartup(typeof(Startup))]
namespace SHA1CertChecker.Function
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            var config = new ConfigurationBuilder()
               .SetBasePath(Environment.CurrentDirectory)
               .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
               .AddUserSecrets(Assembly.GetExecutingAssembly(), true)
               .AddEnvironmentVariables()
               .Build();
            
            builder.Services.AddSingleton(config);
        }
    }
}