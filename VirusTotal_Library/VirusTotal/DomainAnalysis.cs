using Newtonsoft.Json.Linq;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using VirusTotal_Library.Structs;

namespace VirusTotal_Library.VirusTotal
{
    public class DomainAnalysis : VirusTotalWrapper
    {

        public DomainAnalysis(string apiKey) : base(apiKey)
        {
        }

        public async Task<string> GetDomainReportJsonString(string domain)
        {
            string a = "";
            var requestResultDomain = await _client.GetAsync("domains/" + domain);
            if (requestResultDomain.IsSuccessStatusCode)
            {
                a = await requestResultDomain.Content.ReadAsStringAsync();
            }
            return a;
        }

        public async Task<DomainScanResult> GetDomainReport(string domain)
        {
            var jsonString = await GetDomainReportJsonString(domain);
            JObject data = JObject.Parse(jsonString);

            var getAttributes = data["data"]["attributes"];
            var get_analysis_stats = ((JObject)getAttributes["last_analysis_stats"]);

            // __ Array ______
            var getEngines = ((JObject)getAttributes["last_analysis_results"]).Properties();
            var getPupularityRanks = ((JObject)getAttributes["popularity_ranks"]).Properties();
            var getCategories = ((JObject)getAttributes["categories"]).Properties();
            var getTags = getAttributes["tags"].ToObject<string[]>();
            var getLast_Dns_Records = getAttributes["last_dns_records"].ToObject<List<DnsRecord>>();


            // __ Array ______

            DomainScanResult domainScanResult= new DomainScanResult();

            domainScanResult.DomainId = (string)data["data"]["id"];
            domainScanResult.Reputation = (int)getAttributes["reputation"];
            domainScanResult.Tags = getTags;
            domainScanResult.Tld = (string)getAttributes["tld"];
            domainScanResult.Jarm = (string)getAttributes["jarm"];
            domainScanResult.DnsRecordsDate = ConvertTimeStampsToDateTime((long)getAttributes["last_dns_records_date"]);
            domainScanResult.LastAnalysisDate = ConvertTimeStampsToDateTime((long)getAttributes["last_analysis_date"]);
            domainScanResult.HttpsCertificateDate = ConvertTimeStampsToDateTime((long)getAttributes["last_https_certificate_date"]);
            domainScanResult.LastModificationDate = ConvertTimeStampsToDateTime((long)getAttributes["last_modification_date"]);
            domainScanResult.AnalysisDate = ConvertTimeStampsToDateTime((long)getAttributes["last_analysis_date"]);

            AnalysisStatis analysisStat = new AnalysisStatis();
            analysisStat.Harmless = (int)get_analysis_stats["harmless"];
            analysisStat.Malicious = (int)get_analysis_stats["malicious"];
            analysisStat.Suspicious = (int)get_analysis_stats["suspicious"];
            analysisStat.TimeOut = (int)get_analysis_stats["timeout"];
            analysisStat.Undetected = (int)get_analysis_stats["undetected"];
            domainScanResult.AnalysisStats = analysisStat;


            var engineRes = new List<EnginerResult>();
            foreach (var engine in getEngines)
            {
                engineRes.Add(new EnginerResult
                {
                    EngineName = engine.Name,
                    Category = (string)engine.Value["category"],
                    Result = (string)engine.Value["result"],
                    Method = (string)engine.Value["method"],
                    EngineUpdate = (string)engine.Value["engine_update"],
                });
            }
            domainScanResult.EnginerResults = engineRes;

            var categories = new List<Category>();
            foreach (var category in getCategories)
            {
                categories.Add(new Category
                {
                    CategoryName = category.Name,
                    Description = (string)category.Value
                });
            }
            domainScanResult.Categories = categories;

            var dnsRecords = new List<DnsRecord>();
            foreach (var dnsRecord in getLast_Dns_Records)
            {
                dnsRecords.Add(new DnsRecord
                {
                    Type = dnsRecord.Type,
                    Value = dnsRecord.Value,
                    Ttl = dnsRecord.Ttl,
                    Priority = dnsRecord.Priority,
                    Rname = dnsRecord.Rname,
                    Serial = dnsRecord.Serial,
                    Refresh = dnsRecord.Refresh,
                    Retry = dnsRecord.Retry,
                    Expire = dnsRecord.Expire,
                    Minimum = dnsRecord.Minimum
                });
            }
            domainScanResult.DnsRecords = dnsRecords;

            var popularityRanks = new List<PopularityRank>();
            foreach (var popularityRank in getPupularityRanks)
            {
                popularityRanks.Add(new PopularityRank
                {
                    RankName = popularityRank.Name,
                    TimeStamp = (int)popularityRank.Value["timestamp"],
                    Rank = (int)popularityRank.Value["rank"]
                });
            }
            domainScanResult.PopularityRanks = popularityRanks;

            return domainScanResult;
        }
    }
}
