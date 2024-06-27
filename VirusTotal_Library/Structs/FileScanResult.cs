using System;
using System.Collections.Generic;

namespace VirusTotal_Library.Structs
{
    public struct FileScanResult
    {
        public string Md5 { get; set; }
        public string Sha1 { get; set; }
        public string Sha256 { get; set; }
        public string Size { get; set; }
        public string Magika { get; set; }
        public string MeaningfulName { get; set; }


        public string TimesSubmitted { get; set; }
        public List<EnginerResult> EngineResults { get; set; }
        public string LastModificationDate { get; set; }

        public string Ssdeep { get; set; }
        public string TypeTag { get; set; }
        public string TypeTags { get; set; }
        public string Tlsh { get; set; }
        public string TypeDescription { get; set; }
        public string Reputation { get; set; }

        public DateTime Date { get; set; }
        public DateTime FirstSubmissionDate { get; set; }
        public DateTime LastAnalysisDate { get; set; }
        public DateTime LastSubmissionDate { get; set; }

        public string Tags { get; set; }

        public string Magic { get; set; }
        public string TypeExtension { get; set; }

        public AnalysisStatis AnalysisStatis { get; set; }

        public SignatureInfo SignatureInfo { get; set; }

        public string[] Names { get; set; }

    }

    public struct SignatureInfo
    {
        public string Description { get; set; }
        public string FileVersion { get; set; }
        public string OriginalName { get; set; }
        public string Product { get; set; }
        public string InternalName { get; set; }

    }

    public struct AnalysisStatis
    {
        public int Harmless { get; set; }
        public int Malicious { get; set; }
        public int Undetected { get; set; }
        public int Suspicious { get; set; }
        public int TimeOut { get; set; }
        public int Failure { get; set; }
        public int TypeUnsupported { get; set; }
        public int Confirmed_TimeOut { get; set; }
    }


}
