// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;

namespace NuGet.Jobs.Validation.PackageSigning.Validation
{
    public interface ISignatureValidator
    {
        SignatureValidationResult ValidateSignature(X509Certificate2 certificate);
    }
}
