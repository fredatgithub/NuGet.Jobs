// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace NuGet.Jobs.Validation.PackageSigning.Validation
{
    public class SignatureValidator
        : ISignatureValidator
    {
        private const string SignatureTimestampOid = "1.2.840.113549.1.9.16.2.14";

        private readonly ILogger<SignatureValidator> _logger;

        public SignatureValidator(ILogger<SignatureValidator> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public SignatureValidationResult ValidateSignature(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            var result = new SignatureValidationResult();

            var verifyCms = new SignedCms();
            verifyCms.Decode(certificate.RawData);

            /*
            * The “SignedAt” property should be the time that the signature was created, according to the trusted timestamp authority. 
            * This is the signature.p7s’s "signature time-stamp" unsigned attribute of the SignerInfo, with attribute OID 1.2.840.113549.1.9.16.2.14.
            */

            if (verifyCms.SignerInfos == null || verifyCms.SignerInfos.Count > 1)
            {
                result.IsValid = false;
                result.ValidationErrorMessage = "The signed CMS object must have exactly 1 SignatureInfo object.";

                return result;
            }

            var unsignedAttributes = verifyCms.SignerInfos[0].UnsignedAttributes;
            if (unsignedAttributes == null || unsignedAttributes.Count > 1)
            {
                result.IsValid = false;
                result.ValidationErrorMessage = "The signature SHOULD NOT contain additional unsigned attributes.";

                return result;
            }

            var unsignedAttribute = unsignedAttributes[0];
            if (unsignedAttribute.Oid.Value == SignatureTimestampOid)
            {
                //unsignedAttribute.Values[0].r
            }

            return result;
        }
    }
}
