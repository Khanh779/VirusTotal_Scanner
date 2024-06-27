using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VirusTotal_Library.Structs
{
    public struct DomainScanResult
    {
        public string DomainId { get; set; }
        public int Reputation { get; set; }
        public DateTime DnsRecordsDate { get; set; }
        public string Tld { get; set; }
        public string Jarm { get; set; }

        public DateTime LastAnalysisDate { get; set; }
        public DateTime HttpsCertificateDate { get; set; }
        public DateTime LastModificationDate { get; set; }
        public DateTime AnalysisDate { get; set; }

        public AnalysisStatis AnalysisStats { get; set; }

        public List<EnginerResult> EnginerResults { get; set; }
        public List<Category> Categories { get; set; }
        public string[] Tags { get; set; }
        public List<DnsRecord> DnsRecords { get; set; }

        public List<PopularityRank> PopularityRanks { get; set; }
    }

    public struct DnsRecord
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public int Ttl { get; set; }
        public int? Priority { get; set; } 
        public string Rname { get; set; }   
        public int? Serial { get; set; }    
        public int? Refresh { get; set; } 
        public int? Retry { get; set; }   
        public int? Expire { get; set; }   
        public int? Minimum { get; set; }  
    }


    public struct PopularityRank
    {
        public string RankName { get; set; }
        public int TimeStamp { get; set; }
        public int Rank { get; set;}
    }
}
