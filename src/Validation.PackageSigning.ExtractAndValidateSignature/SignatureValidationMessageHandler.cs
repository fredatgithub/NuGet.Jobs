// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Jobs.Validation.Common;
using NuGet.Jobs.Validation.PackageSigning.ExtractAndValidateSignature.Storage;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Jobs.Validation.PackageSigning.Storage;
using NuGet.Packaging;
using NuGet.Services.ServiceBus;
using NuGet.Services.Validation;

namespace NuGet.Jobs.Validation.PackageSigning.ExtractAndValidateSignature
{
    /// <summary>
    /// The handler for <see cref="SignatureValidationMessage"/>.
    /// Upon receiving a message, this will extract all metadata (including certificates) from a nupkg, 
    /// and verify the <see cref="PackageSignature"/> using extracted metadata. 
    /// This doesn't do online revocation checks.
    /// </summary>
    public class SignatureValidationMessageHandler
        : IMessageHandler<SignatureValidationMessage>
    {
        private const int DefaultMaximumValidationFailures = 5;

        private readonly IValidationEntitiesContext _validationContext;
        private readonly IValidatorStateService _validatorStateService;
        private readonly IPackageSigningStateService _packageSigningStateService;
        private readonly ICertificateValidationService _certificateValidationService;
        private readonly ICertificateStore _certificateStore;
        private readonly ILogger<SignatureValidationMessageHandler> _logger;
        private readonly int _maximumValidationFailures;

        /// <summary>
        /// Instantiate's a new package signatures validator.
        /// </summary>
        /// <param name="validationContext">The persisted validation context.</param>
        /// <param name="certificateStore">The persisted certificate store.</param>
        /// <param name="validatorStateService">The service used to persist this validator's state.</param>
        public SignatureValidationMessageHandler(
            IValidationEntitiesContext validationContext,
            IValidatorStateService validatorStateService,
            IPackageSigningStateService packageSigningStateService,
            ICertificateStore certificateStore,
            ICertificateValidationService certificateValidationService,
            ILogger<SignatureValidationMessageHandler> logger,
            int maximumValidationFailures = DefaultMaximumValidationFailures)
        {
            //ISubscriptionProcessor<SignatureValidationMessage> subscriptionProcessor,
            //_subscriptionProcessor = subscriptionProcessor ?? throw new ArgumentNullException(nameof(subscriptionProcessor));
            _validationContext = validationContext ?? throw new ArgumentNullException(nameof(validationContext));
            _validatorStateService = validatorStateService ?? throw new ArgumentNullException(nameof(validatorStateService));
            _packageSigningStateService = packageSigningStateService ?? throw new ArgumentNullException(nameof(packageSigningStateService));
            _certificateValidationService = certificateValidationService ?? throw new ArgumentNullException(nameof(certificateValidationService));
            _certificateStore = certificateStore ?? throw new ArgumentNullException(nameof(certificateStore));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _maximumValidationFailures = maximumValidationFailures;
        }

        /// <summary>
        /// Extract the package metadata and verify signature.
        /// </summary>
        /// <param name="message">The message requesting the signature verification.</param>
        /// <returns>
        /// Returns <c>true</c> if the validation completed; otherwise <c>false</c>.
        /// If <c>false</c>, the validation should be retried later.
        /// </returns>
        public async Task<bool> HandleAsync(SignatureValidationMessage message)
        {
            // Find the signature validation entity that matches this message.
            var validation = await _validationContext
                .ValidatorStatuses
                .FirstOrDefaultAsync(v => v.ValidationId == message.ValidationId);

            // A signature validation should be queued with ValidatorState == Incomplete.
            if (validation == null)
            {
                _logger.LogInformation(
                    "Could not find validation entity, requeueing (package: {PackageId} {PackageVersion}, validationId: {ValidationId})",
                    message.PackageId,
                    message.PackageVersion,
                    message.ValidationId);

                // Message may be retried.
                return false;
            }
            else if (validation.State != ValidationStatus.Incomplete)
            {
                _logger.LogError(
                    "Invalid signature verification status '{ValidatorState}' when 'Incomplete' was expected, dropping message (package id: {PackageId} package version: {PackageVersion} validation id: {ValidationId})",
                    validation.State,
                    message.PackageId,
                    message.PackageVersion,
                    message.ValidationId);

                // Consume the message.
                return true;
            }

            // Validate package
            using (var packageArchiveReader = await DownloadPackageAsync(message.NupkgUri))
            {
                // TODO: consume actual client nupkg's containing missing signing APIs
                if (!await packageArchiveReader.IsSignedAsync(CancellationToken.None))
                {
                    return await HandleUnsignedPackageAsync(validation, message);
                }
                else
                {
                    // TODO: extract signatures from nupkg
                    var signatures = await packageArchiveReader.GetSignaturesAsync(CancellationToken.None);

                    // TODO: store extracted signatures
                    // ...
                    foreach (var signature in signatures)
                    {
                        await _certificateStore.Save(signature);
                    }

                    using (var signedPackage = new SignedPackageArchive(zip))
                    {
                        var trustProviders = new[] { new SignatureVerificationProvider() };
                        var signedPackageVerifier = new SignedPackageVerifier(trustProviders, SignedPackageVerifierSettings.RequireSigned);

                        // TODO: verify signatures client-side
                        var verifySignaturesResult = await signedPackageVerifier.VerifySignaturesAsync(packageArchiveReader, _logger, CancellationToken.None);

                        // TODO: handle client-side signature verification result
                        if (!verifySignaturesResult.Valid)
                        {
                            return await HandleInvalidPackageSignatureAsync(validation, message);
                        }
                        else
                        {
                            return await HandleValidPackageSignatureAsync(validation, message, signatures);
                        }
                    }
                }
            }
        }

        private async Task<bool> HandleUnsignedPackageAsync(ValidatorStatus validation, SignatureValidationMessage message)
        {
            _logger.LogInformation(
                        "Package {PackageId} {PackageVersion} is unsigned, no additional validations necessary.",
                        message.PackageId,
                        message.PackageVersion);

            var savePackageSigningStateResult = await _packageSigningStateService.TrySetPackageSigningState(
                validation.PackageKey,
                message,
                /*isRevalidating*/ false,
                PackageSigningStatus.Unsigned);

            validation.State = ValidationStatus.Succeeded;
            await _validatorStateService.SaveStatusAsync(validation);

            // Consume the message.
            return true;
        }

        private async Task<bool> HandleInvalidPackageSignatureAsync(ValidatorStatus validation, SignatureValidationMessage message)
        {
            _logger.LogInformation(
                        "Signature for package {PackageId} {PackageVersion} is invalid.",
                        message.PackageId,
                        message.PackageVersion);

            // Revalidation failed?
            if (await _validatorStateService.IsRevalidationRequestAsync(validation.PackageKey, message.ValidationId))
            {
                var currentState = _validationContext.PackageSigningStates.FirstOrDefault(s => s.PackageKey == validation.PackageKey);
                if (currentState != null)
                {
                    // TODO:
                    // if failure is due to certificate issue
                    // then UPDATE Certificate SET Status = Invalid

                    var savePackageSigningStateResult = await _packageSigningStateService.TrySetPackageSigningState(
                        validation.PackageKey,
                        message,
                        /*isRevalidating*/ true,
                        PackageSigningStatus.Invalid);

                    foreach (var signature in await _validationContext.PackageSignatures.Where(s => s.PackageKey == validation.PackageKey).ToListAsync())
                    {
                        signature.Status = PackageSignatureStatus.Invalid;
                    }

                    await _validationContext.SaveChangesAsync();
                }
            }

            validation.State = ValidationStatus.Failed;
            await _validatorStateService.SaveStatusAsync(validation);

            // Consume the message.
            return true;
        }

        private async Task<bool> HandleValidPackageSignatureAsync(ValidatorStatus validation, SignatureValidationMessage message, IReadOnlyCollection<X509Certificate2> signatures)
        {
            // Check for revalidation.
            var isRevalidation = await _validatorStateService.IsRevalidationRequestAsync(validation.PackageKey, message.ValidationId);

            // There will be only one during wave 1
            foreach (var signature in signatures)
            {
                // TODO: get the end certificate used to create the signature
                X509Certificate2 endCertificate;

                // TODO:
                // if either signature or timestamp authority certificates is expired AND this is not a revalidation
                var certificateValidationResult = await _certificateValidationService.VerifyAsync(endCertificate);

                if (!isRevalidation && certificateValidationResult != CertificateVerificationResult.Good)
                {
                    //  UPDATE ValidatorStatuses SET State = Failed
                    validation.State = ValidationStatus.Failed;
                    await _validatorStateService.SaveStatusAsync(validation);

                    //  Consume service bus message
                    return true;
                }
                else
                {
                    PackageSignature packageSignature = await _validationContext.PackageSignatures.SingleOrDefaultAsync(ps => ps.PackageKey = message.)
                    if (packageSignature != null)
                    {
                        // This may happen in revalidation flow.
                        packageSignature.Status = PackageSignatureStatus.Unknown;

                        // TODO: SignedAt...
                    }
                    else
                    {
                        packageSignature = new PackageSignature
                        {
                            Status = PackageSignatureStatus.Unknown,

                            // TODO: SignedAt...
                        };

                        _validationContext.PackageSignatures.Add(packageSignature);
                    }

                    await _validationContext.SaveChangesAsync();
                }
            }

            var savePackageSigningStateResult = await _packageSigningStateService.TrySetPackageSigningState(validation.PackageKey, message, isRevalidation, PackageSigningStatus.Valid);

            validation.State = ValidationStatus.Succeeded;
            await _validatorStateService.SaveStatusAsync(validation);

            // Consume the message.
            return true;
        }

        private async Task<PackageArchiveReader> DownloadPackageAsync(Uri nupkgUri)
        {
            Stream packageStream;
            using (var httpClient = new HttpClient())
            {
                // Download nupkg using URL given in queue
                packageStream = await httpClient.GetStreamAsync(nupkgUri);

                _logger.LogInformation($"Downloaded package from {{{TraceConstant.Url}}}", nupkgUri);
            }

            packageStream.Position = 0;

            return new PackageArchiveReader(packageStream);
        }

    }
}
