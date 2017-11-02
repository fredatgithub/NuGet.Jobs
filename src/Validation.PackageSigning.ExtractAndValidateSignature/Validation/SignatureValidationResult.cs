// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace NuGet.Jobs.Validation.PackageSigning.Validation
{
    public class SignatureValidationResult
    {
        public bool IsValid { get; set; }
        public string ValidationErrorMessage { get; set; }
        public DateTime SignedAt { get; set; }
    }
}
