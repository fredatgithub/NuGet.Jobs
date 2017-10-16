﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NuGet.Jobs.Validation.PackageSigning.Storage;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.Configuration;
using NuGet.Services.KeyVault;
using NuGet.Services.ServiceBus;
using NuGet.Services.Validation;
using System.Diagnostics;

namespace NuGet.Jobs.Validation.PackageSigning.ExtractAndValidateSignature
{
    public class Job : JobBase
    {
        private ISubscriptionProcessor<SignatureValidationMessage> _processor;

        /// <summary>
        /// The configured service provider, used to instiate the services this job depends on.
        /// </summary>
        private IServiceProvider _serviceProvider;

        /// <summary>
        /// The argument this job uses to determine the configuration file's path.
        /// </summary>
        private const string ConfigurationArgument = "Configuration";

        /// <summary>
        /// The maximum time that a KeyVault secret will be cached for.
        /// </summary>
        private static readonly TimeSpan KeyVaultSecretCachingTimeout = TimeSpan.FromDays(1);

        /// <summary>
        /// How quickly the shutdown task should check its status.
        /// </summary>
        private static readonly TimeSpan ShutdownPollTime = TimeSpan.FromSeconds(1);

        /// <summary>
        /// The maximum amount of time that graceful shutdown can take before the job will
        /// forcefully end itself.
        /// </summary>
        private static readonly TimeSpan MaxShutdownTime = TimeSpan.FromMinutes(1);

        public override void Init(IDictionary<string, string> jobArgsDictionary)
        {
            var configurationFilename = JobConfigurationManager.GetArgument(jobArgsDictionary, ConfigurationArgument);
            
            _serviceProvider = GetServiceProvider(GetConfigurationRoot(configurationFilename));
        }

        public override async Task Run()
        {
            var processor = _serviceProvider.GetRequiredService<ISubscriptionProcessor<SignatureValidationMessage>>();

            processor.Start();

            // Wait a day, and then shutdown this process so that it is restarted.
            await Task.Delay(TimeSpan.FromDays(1));
            await ShutdownAsync(processor);
        }

        private async Task ShutdownAsync(ISubscriptionProcessor<SignatureValidationMessage> processor)
        {
            await processor.StartShutdownAsync();

            // Wait until all signature validations complete, or, the maximum shutdown time is reached.
            var stopwatch = Stopwatch.StartNew();

            while (processor.NumberOfMessagesInProgress > 0)
            {
                await Task.Delay(ShutdownPollTime);

                Logger.LogInformation(
                    "{NumberOfMessagesInProgress} signature validations in progress after {TimeElapsed} seconds of graceful shutdown",
                    processor.NumberOfMessagesInProgress,
                    stopwatch.Elapsed.Seconds);

                if (stopwatch.Elapsed >= MaxShutdownTime)
                {
                    Logger.LogWarning(
                        "Forcefully shutting down even though there are {NumberOfMessagesInProgress} signature validations in progress",
                        processor.NumberOfMessagesInProgress);

                    return;
                }
            }
        }

        private IConfigurationRoot GetConfigurationRoot(string configurationFilename)
        {
            Logger.LogInformation("Using the {ConfigurationFilename} configuration file", configurationFilename);

            var builder = new ConfigurationBuilder()
                .SetBasePath(Environment.CurrentDirectory)
                .AddJsonFile(configurationFilename, optional: false, reloadOnChange: true);

            var uninjectedConfiguration = builder.Build();

            var secretReaderFactory = new ConfigurationRootSecretReaderFactory(uninjectedConfiguration);
            var cachingSecretReaderFactory = new CachingSecretReaderFactory(secretReaderFactory, KeyVaultSecretCachingTimeout);
            var secretInjector = cachingSecretReaderFactory.CreateSecretInjector(cachingSecretReaderFactory.CreateSecretReader());

            builder = new ConfigurationBuilder()
                .SetBasePath(Environment.CurrentDirectory)
                .AddInjectedJsonFile(configurationFilename, secretInjector);

            return builder.Build();
        }

        private void ConfigureJobServices(IServiceCollection services, IConfigurationRoot configurationRoot)
        {
            services.AddTransient<ISubscriptionProcessor<SignatureValidationMessage>, SubscriptionProcessor<SignatureValidationMessage>>();

            services.AddScoped<IValidationEntitiesContext>(p =>
            {
                var config = p.GetRequiredService<IOptionsSnapshot<ValidationDbConfiguration>>().Value;

                return new ValidationEntitiesContext(config.ConnectionString);
            });

            services.AddTransient<ISubscriptionClient>(p =>
            {
                var config = p.GetRequiredService<IOptionsSnapshot<ServiceBusConfiguration>>().Value;

                return new SubscriptionClientWrapper(config.ConnectionString, config.TopicPath, config.SubscriptionName);
            });

            services.AddTransient<IBrokeredMessageSerializer<SignatureValidationMessage>, SignatureValidationMessageSerializer>();
            services.AddTransient<IMessageHandler<SignatureValidationMessage>, SignatureValidationMessageHandler>();
            services.AddTransient<IPackageSigningStateService, PackageSigningStateService>();

            services.AddTransient<ICertificateStore, CertificateStore>();
            services.AddTransient<ICertificateValidationService, CertificateValidationService>();
            //services.AddTransient<IAlertingService, AlertingService>();
        }

        private IServiceProvider GetServiceProvider(IConfigurationRoot configurationRoot)
        {
            var services = new ServiceCollection();

            ConfigureLibraries(services);
            ConfigureJobServices(services, configurationRoot);

            return CreateProvider(services);
        }

        private void ConfigureLibraries(IServiceCollection services)
        {
            // Use the custom NonCachingOptionsSnapshot so that KeyVault secret injection works properly.
            services.Add(ServiceDescriptor.Scoped(typeof(IOptionsSnapshot<>), typeof(NonCachingOptionsSnapshot<>)));
            services.AddSingleton(LoggerFactory);
            services.AddLogging();
        }

        private static IServiceProvider CreateProvider(IServiceCollection services)
        {
            var containerBuilder = new ContainerBuilder();

            containerBuilder.Populate(services);

            return new AutofacServiceProvider(containerBuilder.Build());
        }
    }
}
