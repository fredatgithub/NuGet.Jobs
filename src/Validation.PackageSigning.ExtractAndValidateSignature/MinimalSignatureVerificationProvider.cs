﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Packaging.Signing;

namespace NuGet.Jobs.Validation.PackageSigning.ExtractAndValidateSignature
{
    /// <summary>
    /// A signature verification provider which performs no verification at all. It allows amount of verification to be
    /// done by <see cref="IPackageSignatureVerifier"/> before performing more in-depth analysis.
    /// </summary>
    public class MinimalSignatureVerificationProvider : ISignatureVerificationProvider
    {
        public Task<PackageVerificationResult> GetTrustResultAsync(
            ISignedPackageReader package,
            Signature signature,
            SignedPackageVerifierSettings settings,
            CancellationToken token)
        {
            var result = new SignedPackageVerificationResult(
                SignatureVerificationStatus.Trusted,
                signature,
                Enumerable.Empty<SignatureLog>());

            return Task.FromResult<PackageVerificationResult>(result);
        }
    }
}