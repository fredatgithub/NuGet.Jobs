﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

namespace NuGet.Monitoring.RebootSearchInstance
{
    public interface IFeedClient
    {
        Task<DateTimeOffset> GetLatestFeedTimeStampAsync();
    }
}