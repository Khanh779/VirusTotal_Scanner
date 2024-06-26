﻿using System;
using System.Collections.Generic;

namespace VirusTotal_Library.Structs
{
    public struct URLScanResult
    {
        public string Title { get; set; }
        public string Url { get; set; }
        public string Permalink { get; set; }
        public string Resource { get; set; }
        public int ResponseCode { get; set; }

        public int Reputation { get; set; }

        public string ScanId { get; set; }
        public List<EnginerResult> EngineResults { get; set; }

        public string[] OutgoingLinks { get; set; }
        public string[] RedirectionChain { get; set; }
        public string[] Tags { get; set; }

        public List<Category> Categories { get; set; }

        public AnalysisStatis AnalysisStatis { get; set; }

        public DateTime Date { get; set; }

        public DateTime LastSubmissionDate { get; set; }
        public DateTime LastModificationDate { get; set; }
        public DateTime LastAnalysisDate { get; set; }

        public int TimesSubmitted { get; set; }
        public string Tld { get; set; }

        public string[] ThreatNames { get; set; }

        public HttpResponseHeaders HttpResponseHeaders { get; set; }


    }

    public struct HttpResponseHeaders
    {
        public string ContentType { get; set; }
        public string ContentSecurityPolicyReportOnly { get; set; }
        public string AcceptCH { get; set; }
        public string PermissionsPolicy { get; set; }
        public string P3P { get; set; }
        public string ContentEncoding { get; set; }
        public DateTime Date { get; set; }
        public string Server { get; set; }
        public int ContentLength { get; set; }
        public string XXSSProtection { get; set; }
        public string XFrameOptions { get; set; }
    
        public string CacheControl { get; set; }
        public string SetCookie { get; set; }
        public string AltSvc { get; set; }
    }

    public struct Category
    {
        public int Index { get; set; }
        public string CategoryName { get; set; }
        public string Description { get; set; }
    }

    public struct URLInfo
    {
        public string Id { get; set; }
        public string Url { get; set; }

        public string Sha256 { get; set; }
    }
}
