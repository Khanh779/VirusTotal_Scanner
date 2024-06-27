using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotal_Library.Structs
{
    public struct IpAddressResult
    {
        public string IpId { get; set; }
        public DateTime WhoIsDate { get; set; }
        public string Reputation { get; set; }
        public string WhoIs { get; set; }
        public DateTime LastAnalysisDate { get; set; }
        public string[] Tags { get; set; }

        public AnalysisStatis AnalysisStatis { get; set;    }
        public List<EnginerResult> EngineResults { get; set; }
        public DateTime LastModificationDate { get; set; }

    }
}
